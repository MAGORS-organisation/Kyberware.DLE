using System.Collections.Concurrent;
using System.Net;
using System.Text.RegularExpressions;

using Dle.Edge.Configuration;

using Microsoft.Extensions.Options;

using UAParser;

namespace Dle.Edge.Clients;

/// <summary>
/// Turns a transport-neutral <see cref="ClientRequest"/> into the <see cref="ClientContext"/> the
/// routing engine and the click stream both consume.
/// </summary>
/// <remarks>
/// <para>
/// The classification budget is 1.5 ms for user agent parsing and the geographic lookup
/// together, out of a 5.5 ms p50. User agent parsing is a cascade of regular expressions and would
/// eat most of that on its own, so the parse result is memoised: real traffic sends a few thousand
/// distinct user agent strings, and the same handful account for the overwhelming majority of
/// requests.
/// </para>
/// <para>
/// The memo is keyed by a 64-bit FNV-1a hash of the string rather than by the string itself. That
/// bounds the memory a cached entry costs regardless of how long a client makes its user agent, and
/// the cache is capacity-bounded on top of that because the key space is attacker controlled — a
/// client that sends a fresh user agent per request must not be able to grow a dictionary without
/// limit.
/// </para>
/// <para>
/// Crawler <em>detection</em> happens here, crawler <em>confirmation</em> does not: confirming a
/// claim needs DNS, and this interface is synchronous by contract. The pipeline calls
/// <see cref="IBotVerifier"/> afterwards and rewrites the two flags.
/// </para>
/// </remarks>
public sealed class ClientClassifier : IClientClassifier
{
    private const ulong FnvOffsetBasis = 14695981039346656037UL;
    private const ulong FnvPrime = 1099511628211UL;

    /// <summary>How long one regular expression may run before the parser gives up on it.</summary>
    /// <remarks>
    /// The guard against a pathological string: a regular expression cascade over attacker-controlled
    /// input is a denial-of-service primitive without one. The parser gives up silently and tries the
    /// next expression, so an answer can lack the match that decided it. That happens far more often
    /// than the limit suggests: the runtime measures it with a clock that moves in steps of 4 to 16 ms,
    /// so an expression that runs for a fraction of a millisecond across a step is dropped too, and so is
    /// one that is being compiled. <see cref="Describe"/> therefore watches for drops rather than time.
    /// </remarks>
    internal static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(5);

    /// <summary>
    /// The user agents the warm-up parses besides noise. An expression that looks for a literal is
    /// not compiled until a string containing it arrives, so the common literals are all here.
    /// </summary>
    private static readonly string[] WarmUpUserAgents =
    [
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Instagram 340.0.0.24.109",
        "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 14; SM-X710) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; Lumia 950) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15063",
        "Mozilla/5.0 (Mobile; LYF/F300B/LYF-F300B-001-01-15-130718-i;Android; rv:48.0) Gecko/48.0 Firefox/48.0 KAIOS/2.5",
        "Mozilla/5.0 (SMART-TV; LINUX; Tizen 6.0) AppleWebKit/537.36 (KHTML, like Gecko) 76.0.3809.146/6.0 TV Safari/537.36",
        "okhttp/4.12.0",
        "Go-http-client/2.0",
    ];

    /// <summary>
    /// One parser for the process. Building it and compiling its expressions is the expensive part, it
    /// has no state per classifier, and it is safe to share between threads.
    /// </summary>
    private static readonly Lazy<Parser> SharedParser = new(static () => Parser.GetDefault(new ParserOptions
    {
        // The compiled regular expressions cost more to build and are markedly faster to run, which
        // is the right trade for a process that parses user agents for its whole lifetime.
        UseCompiledRegex = true,
        MatchTimeOut = MatchTimeout,
    }));

    private readonly IGeoIpResolver _geoIp;
    private readonly Func<string, UserAgentFacts> _parse;
    private readonly int _capacity;
    private readonly ConcurrentDictionary<ulong, UserAgentFacts> _memo = new();

    /// <summary>
    /// Creates the classifier.
    /// </summary>
    /// <param name="geoIp">Geographic resolver; may be permanently unavailable.</param>
    /// <param name="options">Edge options; supplies the memo capacity.</param>
    /// <exception cref="ArgumentNullException">An argument is <see langword="null"/>.</exception>
    public ClientClassifier(IGeoIpResolver geoIp, IOptions<EdgeOptions> options)
        : this(geoIp, options, parse: null)
    {
    }

    /// <summary>Creates the classifier over a parser the caller controls.</summary>
    /// <param name="geoIp">Geographic resolver; may be permanently unavailable.</param>
    /// <param name="options">Edge options; supplies the memo capacity.</param>
    /// <param name="parse">Parses one user agent, or <see langword="null"/> for the real parser.</param>
    /// <exception cref="ArgumentNullException">An argument other than <paramref name="parse"/> is <see langword="null"/>.</exception>
    internal ClientClassifier(
        IGeoIpResolver geoIp,
        IOptions<EdgeOptions> options,
        Func<string, UserAgentFacts>? parse)
    {
        ArgumentNullException.ThrowIfNull(geoIp);
        ArgumentNullException.ThrowIfNull(options);

        DroppedExpressions.StartCounting();

        _geoIp = geoIp;
        _parse = parse ?? Parse;
        _capacity = options.Value.UserAgentCacheCapacity;
    }

    /// <summary>
    /// Runs the parser over input that makes it compile its regular expressions, without keeping any
    /// answer.
    /// </summary>
    /// <remarks>
    /// The parser compiles each expression the first time it runs it, and a string that matches
    /// nothing runs the whole cascade, so without this the first requests after start-up wait for all
    /// of it: about a second and a half in a container. While that is going on an expression can also run
    /// past <see cref="MatchTimeout"/> because it is being compiled, which loses a match and makes the
    /// answer wrong. Nothing parsed here goes into the memo, because those are the answers that may be wrong.
    /// </remarks>
    /// <param name="cancellationToken">Cancelled when the host gives up starting.</param>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    internal void WarmUp(CancellationToken cancellationToken)
    {
        // Noise first: it pays for nearly all of the cascade on its own.
        foreach (int length in (ReadOnlySpan<int>)[1024, 512, 128, 16])
        {
            cancellationToken.ThrowIfCancellationRequested();
            _ = _parse(WarmUpNoise(length));
        }

        foreach (string userAgent in WarmUpUserAgents)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _ = _parse(userAgent);
        }
    }

    /// <summary>Printable text that contains no token a user agent expression looks for.</summary>
    private static string WarmUpNoise(int length) =>
        string.Create(length, 0, static (span, _) =>
        {
            for (int i = 0; i < span.Length; i++)
            {
                span[i] = (char)('a' + ((i * 7) % 26));
            }
        });

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException"><paramref name="request"/> is <see langword="null"/>.</exception>
    public ClientContext Classify(ClientRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        UserAgentFacts facts = Describe(request.UserAgent);
        GeoLocation? location = _geoIp.Resolve(request.RemoteIp);

        return new ClientContext
        {
            Platform = facts.Platform,
            DeviceClass = facts.DeviceClass,
            Channel = facts.Channel,
            UaFamily = facts.UaFamily,
            OsFamily = facts.OsFamily,
            OsVersion = facts.OsVersion,
            AppVersion = facts.AppVersion,
            Country = location?.Country,
            Region = location?.Region,
            Language = PrimaryLanguage(request.AcceptLanguage),
            ReferrerHost = ReferrerHost(request.Referrer),
            IsCrawler = facts.CrawlerName is not null,
            IsSpoofedBot = false,
            CrawlerName = facts.CrawlerName,
            RemoteIp = request.RemoteIp,
            Query = request.Query,
            ReceivedAt = request.ReceivedAt,
        };
    }

    /// <summary>
    /// Returns the parsed facts about one user agent string, parsing it at most once per capacity
    /// generation.
    /// </summary>
    private UserAgentFacts Describe(string? userAgent)
    {
        if (string.IsNullOrEmpty(userAgent))
        {
            return UserAgentFacts.Unknown;
        }

        ulong key = Hash(userAgent);

        if (_memo.TryGetValue(key, out UserAgentFacts? cached))
        {
            return cached;
        }

        int dropped = DroppedExpressions.OnThisThread;
        UserAgentFacts facts = _parse(userAgent);

        if (DroppedExpressions.OnThisThread != dropped)
        {
            // The parser dropped an expression (see MatchTimeout), so this answer may be missing the
            // match that decided it, and the memo would keep it for the life of the generation. A drop
            // comes from the clock or from compiling, not from the string, so the next parse almost
            // always runs clean. Only a clean answer is kept; one that dropped twice is used for this
            // request and parsed again on the next.
            dropped = DroppedExpressions.OnThisThread;
            facts = _parse(userAgent);

            if (DroppedExpressions.OnThisThread != dropped)
            {
                return facts;
            }
        }

        // A generational reset rather than an eviction policy. Least-recently-used bookkeeping on the
        // hot path would cost more than the parse it saves, and the working set of real user agents
        // is far below the capacity, so a reset is a rare event that costs one re-parse per live
        // string. Under a deliberate flood it is exactly the intended behaviour: bounded memory,
        // degraded to no memoisation.
        if (_memo.Count >= _capacity)
        {
            _memo.Clear();
        }

        _ = _memo.TryAdd(key, facts);
        return facts;
    }

    private UserAgentFacts Parse(string userAgent)
    {
        if (CrawlerCatalog.TryMatch(userAgent, out string crawler))
        {
            return new UserAgentFacts
            {
                Platform = Platform.Other,
                DeviceClass = DeviceClass.Bot,
                Channel = ClientChannel.Crawler,
                UaFamily = crawler,
                CrawlerName = crawler,
            };
        }

        string parseableUa = userAgent.Length > 1024 ? userAgent[..1024] : userAgent;
        ClientInfo parsed = SharedParser.Value.Parse(parseableUa);
        Platform platform = ReadPlatform(parsed.OS.Family);
        ClientChannel channel = WebViewCatalog.Classify(userAgent);

        return new UserAgentFacts
        {
            Platform = platform,
            DeviceClass = ReadDeviceClass(parsed, platform, userAgent),
            Channel = channel,
            UaFamily = Blank(parsed.UA.Family),
            OsFamily = Blank(parsed.OS.Family),
            OsVersion = ReadOsVersion(parsed.OS),
            AppVersion = WebViewCatalog.ReadSdkVersion(userAgent),
            CrawlerName = parsed.Device.IsSpider ? "unknown" : null,
        };
    }

    /// <summary>
    /// Maps the operating system family reported by the parser onto the routing platform.
    /// </summary>
    /// <remarks>
    /// The families are matched by prefix because the parser reports variants — "Android",
    /// "Android 12", "Windows 10" — and a routing rule only ever asks the coarse question.
    /// </remarks>
    private static Platform ReadPlatform(string? osFamily)
    {
        if (string.IsNullOrEmpty(osFamily))
        {
            return Platform.Unknown;
        }

        if (osFamily.StartsWith("iOS", StringComparison.OrdinalIgnoreCase) ||
            osFamily.StartsWith("iPadOS", StringComparison.OrdinalIgnoreCase) ||
            osFamily.StartsWith("watchOS", StringComparison.OrdinalIgnoreCase) ||
            osFamily.StartsWith("tvOS", StringComparison.OrdinalIgnoreCase))
        {
            return Platform.Ios;
        }

        if (osFamily.StartsWith("Android", StringComparison.OrdinalIgnoreCase))
        {
            return Platform.Android;
        }

        if (osFamily.StartsWith("Windows", StringComparison.OrdinalIgnoreCase) ||
            osFamily.StartsWith("Mac OS", StringComparison.OrdinalIgnoreCase) ||
            osFamily.StartsWith("macOS", StringComparison.OrdinalIgnoreCase) ||
            osFamily.StartsWith("Linux", StringComparison.OrdinalIgnoreCase) ||
            osFamily.StartsWith("Ubuntu", StringComparison.OrdinalIgnoreCase) ||
            osFamily.StartsWith("Fedora", StringComparison.OrdinalIgnoreCase) ||
            osFamily.StartsWith("Chrome OS", StringComparison.OrdinalIgnoreCase))
        {
            return Platform.Desktop;
        }

        return Platform.Other;
    }

    private static DeviceClass ReadDeviceClass(ClientInfo parsed, Platform platform, string userAgent)
    {
        if (parsed.Device.IsSpider)
        {
            return DeviceClass.Bot;
        }

        string family = parsed.Device.Family ?? string.Empty;

        if (family.Contains("iPad", StringComparison.OrdinalIgnoreCase) ||
            family.Contains("Tablet", StringComparison.OrdinalIgnoreCase) ||
            family.Contains("Kindle", StringComparison.OrdinalIgnoreCase))
        {
            return DeviceClass.Tablet;
        }

        if (family.Contains("iPhone", StringComparison.OrdinalIgnoreCase) ||
            family.Contains("iPod", StringComparison.OrdinalIgnoreCase))
        {
            return DeviceClass.Phone;
        }

        // Android says nothing about form factor in the device family, but every Android phone
        // browser sends the "Mobile" product token and every Android tablet omits it. That is the
        // documented convention and it is the only signal available without client hints.
        if (platform == Platform.Android)
        {
            return userAgent.Contains("Mobile", StringComparison.OrdinalIgnoreCase)
                ? DeviceClass.Phone
                : DeviceClass.Tablet;
        }

        return platform switch
        {
            Platform.Ios => DeviceClass.Phone,
            Platform.Desktop => DeviceClass.Desktop,
            _ => DeviceClass.Unknown,
        };
    }

    /// <summary>
    /// Joins the operating system version parts into the form <see cref="VersionComparer"/> compares.
    /// </summary>
    private static string? ReadOsVersion(OS os)
    {
        if (string.IsNullOrEmpty(os.Major))
        {
            return null;
        }

        string raw = string.IsNullOrEmpty(os.Minor)
            ? os.Major
            : string.IsNullOrEmpty(os.Patch)
                ? string.Concat(os.Major, ".", os.Minor)
                : string.Concat(os.Major, ".", os.Minor, ".", os.Patch);

        return VersionComparer.TryNormalize(raw, out string normalized) ? normalized : null;
    }

    /// <summary>
    /// Reads the primary language subtag from <c>Accept-Language</c>, lowercased.
    /// </summary>
    /// <remarks>
    /// Only the first entry is considered and its quality value is ignored. The header is ordered by
    /// preference in practice, and a routing rule matches a bare subtag such as <c>sk</c>, so parsing
    /// the full <c>q</c> ranking would cost allocations on the hot path for a distinction no rule can
    /// express.
    /// </remarks>
    private static string? PrimaryLanguage(string? acceptLanguage)
    {
        if (string.IsNullOrEmpty(acceptLanguage))
        {
            return null;
        }

        ReadOnlySpan<char> span = acceptLanguage.AsSpan();
        int end = span.IndexOfAny(',', ';');

        if (end >= 0)
        {
            span = span[..end];
        }

        span = span.Trim();

        int dash = span.IndexOf('-');

        if (dash >= 0)
        {
            span = span[..dash];
        }

        if (span.Length is 0 or > 8)
        {
            return null;
        }

        foreach (char c in span)
        {
            if (!char.IsAsciiLetter(c))
            {
                return null;
            }
        }

        return span.ToString().ToLowerInvariant();
    }

    /// <summary>
    /// Reduces the referrer to its host.
    /// </summary>
    /// <remarks>
    /// Only the host is ever kept. A full referrer is never retained, because it can
    /// carry a path and a query string belonging to a page the visitor was reading, and the host is
    /// the only part any report or routing rule uses.
    /// </remarks>
    private static string? ReferrerHost(string? referrer)
    {
        if (string.IsNullOrEmpty(referrer))
        {
            return null;
        }

        if (!Uri.TryCreate(referrer, UriKind.Absolute, out Uri? uri))
        {
            return null;
        }

        return HostNormalizer.TryNormalize(uri.Host, out string normalized) ? normalized : null;
    }

    private static string? Blank(string? value) =>
        string.IsNullOrWhiteSpace(value) || string.Equals(value, "Other", StringComparison.Ordinal) ? null : value;

    /// <summary>
    /// FNV-1a over the UTF-16 code units of the user agent.
    /// </summary>
    /// <remarks>
    /// Not a cryptographic hash and not meant to be: the value never leaves the process and a
    /// collision costs one misclassified user agent, not a security property. It is used instead of
    /// the string itself so that a cached entry has a fixed size no matter how long the header was.
    /// </remarks>
    private static ulong Hash(string value)
    {
        ulong hash = FnvOffsetBasis;

        foreach (char c in value)
        {
            hash = (hash ^ (byte)c) * FnvPrime;
            hash = (hash ^ (byte)(c >> 8)) * FnvPrime;
        }

        return hash;
    }

    /// <summary>
    /// Counts, per thread, the regular expressions that ran past <see cref="MatchTimeout"/>.
    /// </summary>
    /// <remarks>
    /// The parser catches the timeout itself and returns as if the expression had not matched, so the
    /// only way to know an answer lost a match is to see the exception being thrown. It is thrown and
    /// caught on the parsing thread, which makes a per-thread count before and after a parse exact.
    /// The handler sees every exception in the process and does one type check for each.
    /// </remarks>
    private static class DroppedExpressions
    {
        [ThreadStatic]
        private static int s_onThisThread;

        private static int s_counting;

        /// <summary>Expressions dropped on the calling thread so far.</summary>
        internal static int OnThisThread => s_onThisThread;

        /// <summary>Starts counting; later calls do nothing.</summary>
        internal static void StartCounting()
        {
            if (Interlocked.Exchange(ref s_counting, 1) == 0)
            {
                AppDomain.CurrentDomain.FirstChanceException += static (_, e) =>
                {
                    if (e.Exception is RegexMatchTimeoutException)
                    {
                        s_onThisThread++;
                    }
                };
            }
        }
    }
}

/// <summary>
/// Everything the classifier derives from a user agent string alone, memoised per distinct string.
/// </summary>
/// <remarks>
/// Deliberately excludes anything request-specific — address, language, referrer — because those
/// vary per request and caching them against a user agent would leak one visitor's context into
/// another's.
/// </remarks>
public sealed record UserAgentFacts
{
    /// <summary>Facts for a request that sent no user agent at all.</summary>
    public static UserAgentFacts Unknown { get; } = new();

    /// <summary>Routing platform.</summary>
    public Platform Platform { get; init; } = Platform.Unknown;

    /// <summary>Form factor.</summary>
    public DeviceClass DeviceClass { get; init; } = DeviceClass.Unknown;

    /// <summary>Channel the request came through.</summary>
    public ClientChannel Channel { get; init; } = ClientChannel.Unknown;

    /// <summary>Browser family, or the crawler name for a crawler.</summary>
    public string? UaFamily { get; init; }

    /// <summary>Operating system family.</summary>
    public string? OsFamily { get; init; }

    /// <summary>Normalized operating system version.</summary>
    public string? OsVersion { get; init; }

    /// <summary>Application version, when a DLE SDK identified itself in the user agent.</summary>
    public string? AppVersion { get; init; }

    /// <summary>Canonical crawler name the user agent claims to be, if any.</summary>
    public string? CrawlerName { get; init; }
}
