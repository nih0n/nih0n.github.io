+++
title = "ASP.NET Sessions Internals"
date = "2024-08-29T19:45:17-03:00"
author = "Fernando Omori"
authorTwitter = "" #do not include @
cover = ""
coverCaption = ""
description = "Just me learning about sessions"
showFullContent = false
readingTime = false
hideComments = false
color = "" #color from the theme settings
+++

When I was studying how sessions work I wondered: "What is a session id ? A string ? A random number ? What's its format ? Where is it stored ?".
So I procceed to read the ASP.NET source code and I'll tell you what I learned about sessions.

Let's begin with this simple application

```csharp
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSession();
builder.Services.AddDistributedMemoryCache();

var app = builder.Build();

app.UseSession();

app.MapGet("/", (HttpContext context) => TypedResults.Ok(context.Session.GetString("Name")));

app.MapPost("/", (HttpContext context, [FromBody] string value) => context.Session.SetString("Name", value));

app.Run();
```

## Services

We use `.AddSession()` to configure services needed to enable sessions

```csharp
services.TryAddTransient<ISessionStore, DistributedSessionStore>();
services.AddDataProtection(); // This one adds IDataProtectionProvider to the DI container
```

- The `ISessionStore` to persist the session.
- The `IDataProtectionProvider` to encrypt the cookie.

We use `.AddDistributedMemoryCache()` to configure services needed to store the session data

```csharp
services.TryAdd(ServiceDescriptor.Singleton<IDistributedCache, MemoryDistributedCache>());
```

then we call `.UseSession()` to add `SessionMiddleware` to the middleware pipeline, otherwise the session cookie won't be handled.

> Actually the session persistence happens inside `DistributedSession`, the `DistributedSessionStore` just creates a new `DistributedSession` passing the `IDistributedCache`.

### Storage

```csharp
public class DistributedSessionStore : ISessionStore
{
    private readonly IDistributedCache _cache;
    private readonly ILoggerFactory _loggerFactory;

    // ...

    public ISession Create(string sessionKey, TimeSpan idleTimeout, TimeSpan ioTimeout, Func<bool> tryEstablishSession, bool isNewSessionKey)
    {
        if (string.IsNullOrEmpty(sessionKey))
        {
            throw new ArgumentException(Resources.ArgumentCannotBeNullOrEmpty, nameof(sessionKey));
        }

        ArgumentNullException.ThrowIfNull(tryEstablishSession);

        return new DistributedSession(_cache, sessionKey, idleTimeout, ioTimeout, tryEstablishSession, _loggerFactory, isNewSessionKey);
    }
}
```

The `ISessionStore` is responsible for creating a new session object. `DistributedSessionStore` the default implementation of `ISessionStore` creates a new `DistributedSession` (our actual session, a concrete implementation of `ISession`) that is backed by a `DefaultDistributedSessionStore` a key pair structure used to store session data `Dictionary<EncodedKey, byte[]>`.

So when we do

```csharp
context.Session.GetString("Name");
context.Session.SetString("Name", value);
```

That is being handled by `DistributedSession` and stored in `DefaultDistributedSessionStore`.

Usually we use the in-memory implementation `.AddDistributedMemoryCache()` but we can use any implementation of `IDistributedCache`, for example `RedisCache` (from `Microsoft.Extensions.Caching.StackExchangeRedis`) that saves data to a Redis database.

> A `IDistributedCache` implementation **must** be added, else an expection will be throw.

> When data is persisted it gets serialized using what Microsoft calls `SerializeNumAs4Bytes`.

### Security

`IDataProtector` encrypts the cookie using AES-CBC and HMAC-SHA256 to prevent tampering.

### Middleware

Let's take a look in the `SessionMiddleware`, specifically at `Invoke` method where the magic happens

```csharp
public async Task Invoke(HttpContext context)
{
    var isNewSessionKey = false;
    Func<bool> tryEstablishSession = ReturnTrue;
    var cookieValue = context.Request.Cookies[_options.Cookie.Name!];
    var sessionKey = CookieProtection.Unprotect(_dataProtector, cookieValue, _logger);
    if (string.IsNullOrWhiteSpace(sessionKey) || sessionKey.Length != SessionKeyLength)
    {
        sessionKey = GetSessionKey();

        static string GetSessionKey()
        {
            Span<byte> guidBytes = stackalloc byte[16];
            RandomNumberGenerator.Fill(guidBytes);
            return new Guid(guidBytes).ToString();
        }

        cookieValue = CookieProtection.Protect(_dataProtector, sessionKey);
        var establisher = new SessionEstablisher(context, cookieValue, _options);
        tryEstablishSession = establisher.TryEstablishSession;
        isNewSessionKey = true;
    }

    var feature = new SessionFeature();
    feature.Session = _sessionStore.Create(sessionKey, _options.IdleTimeout, _options.IOTimeout, tryEstablishSession, isNewSessionKey);
    context.Features.Set<ISessionFeature>(feature);

    try
    {
        await _next(context);
    }
    finally
    {
        context.Features.Set<ISessionFeature?>(null);

        if (feature.Session != null)
        {
            try
            {
                await feature.Session.CommitAsync();
            }
            catch (OperationCanceledException)
            {
                _logger.SessionCommitCanceled();
            }
            catch (Exception ex)
            {
                _logger.ErrorClosingTheSession(ex);
            }
        }
    }
}
```

First the middleware will initialize some variables

```csharp
var isNewSessionKey = false;
Func<bool> tryEstablishSession = ReturnTrue;
```

- The `isNewSessionKey` is just a flag to say if we are establishing a new session and later will be used to check if we are trying to access a expired session.
- The `tryEstablishSession` is a callback to verify that modifying the session is currently valid.

Then the middleware will try to get a cookie with the name we've set (the default cookie name is `.AspNetCore.Session`)

```csharp
var cookieValue = context.Request.Cookies[_options.Cookie.Name!]
```

At this point we still don't know if the cookie is set, we need to decrypt the cookie to check if it has any value

```csharp
var sessionKey = CookieProtection.Unprotect(_dataProtector, cookieValue, _logger)
```

If the cookie is not set the `sessionKey` will be a `string.Empty` and a new session id will be generated

```csharp
sessionKey = GetSessionKey();

static string GetSessionKey()
{
    Span<byte> guidBytes = stackalloc byte[16];
    RandomNumberGenerator.Fill(guidBytes);
    return new Guid(guidBytes).ToString();
}

cookieValue = CookieProtection.Protect(_dataProtector, sessionKey);
var establisher = new SessionEstablisher(context, cookieValue, _options);
tryEstablishSession = establisher.TryEstablishSession;
isNewSessionKey = true;
```

There it is, the session id is a `Guid`.

Now we encrypt the session id and pass it to `SessionEstablisher`, it will set a callback to set the cookie in the HTTP response.

Now our session is available for the next middlewares

```csharp
var feature = new SessionFeature();
feature.Session = _sessionStore.Create(sessionKey, _options.IdleTimeout, _options.IOTimeout, tryEstablishSession, isNewSessionKey);
context.Features.Set<ISessionFeature>(feature);

try
{
    await _next(context);
}
```

The `HttpContext` is propagated to the next middlewares til it hit our controller where we manage the session using `context.Session`, when our logic is done it's time to unwind the middleware stack til we hit

```csharp
finally
{
    context.Features.Set<ISessionFeature?>(null);

    if (feature.Session != null)
    {
        try
        {
            await feature.Session.CommitAsync();
        }
        catch (OperationCanceledException)
        {
            _logger.SessionCommitCanceled();
        }
        catch (Exception ex)
        {
            _logger.ErrorClosingTheSession(ex);
        }
    }
}
```

And with the statement `await feature.Session.CommitAsync();` we persist our session to our cache storage.