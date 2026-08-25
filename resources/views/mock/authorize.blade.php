@php
    $standard = ['P0.Cp', 'P0.Cd', 'P5.Cp.Cd', 'P5.Cm', 'P9.Cp.Cd', 'P9.Cm'];
    $requested = array_map('strval', $vectors);
    $others = array_values(array_diff($standard, $requested));
    $field = static fn (string $name): string => (string) ($query[$name] ?? '');
@endphp
<!doctype html>
<html lang="en-GB">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Mock NHS login</title>
    <style>
        :root { color-scheme: light dark; }
        * { box-sizing: border-box; }
        body {
            margin: 0; padding: 2rem 1rem; min-height: 100vh;
            font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
            background: #f4f6f8; color: #1a1a1a;
        }
        @media (prefers-color-scheme: dark) { body { background: #16181b; color: #e9edf1; } }
        .card {
            max-width: 34rem; margin: 0 auto; padding: 1.75rem;
            background: #fff; border-radius: 6px; border: 1px solid #d5dbe0;
        }
        @media (prefers-color-scheme: dark) { .card { background: #212429; border-color: #363b42; } }
        .flag {
            max-width: 34rem; margin: 0 auto 1rem; padding: .6rem .9rem; border-radius: 4px;
            background: #ffeb3b; color: #3d3000; font-weight: 600; font-size: .85rem;
            border: 1px solid #d4c21f;
        }
        h1 { font-size: 1.4rem; margin: 0 0 .35rem; }
        .sub { margin: 0 0 1.5rem; font-size: .85rem; opacity: .7; word-break: break-all; }
        fieldset { border: 0; padding: 0; margin: 0 0 1.25rem; }
        legend { font-weight: 600; font-size: .8rem; text-transform: uppercase; letter-spacing: .05em; opacity: .65; padding: 0 0 .5rem; }
        label { display: block; font-size: .82rem; font-weight: 600; margin: 0 0 .3rem; }
        select, input {
            width: 100%; padding: .55rem .7rem; font: inherit; font-size: .92rem;
            border: 1px solid #9aa4ad; border-radius: 4px; background: transparent; color: inherit;
        }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr)); gap: .85rem; }
        .row + .row { margin-top: .85rem; }
        .actions { display: flex; gap: .75rem; flex-wrap: wrap; margin-top: 1.5rem; }
        button { padding: .65rem 1.4rem; font: inherit; font-weight: 600; border-radius: 4px; cursor: pointer; border: 1px solid transparent; }
        .primary { background: #007f3b; color: #fff; }
        .secondary { background: transparent; border-color: #9aa4ad; color: inherit; }
        .meta { margin: 1.25rem 0 0; padding-top: 1rem; border-top: 1px solid #d5dbe0; font-size: .78rem; opacity: .75; }
        @media (prefers-color-scheme: dark) { .meta { border-color: #363b42; } }
        .meta code { word-break: break-all; }
        .warn { color: #a8321a; font-weight: 600; }
    </style>
</head>
<body>
    <p class="flag">Mock issuer — this is not NHS login. Local development only.</p>

    <div class="card">
        <h1>Sign in</h1>
        <p class="sub">{{ $issuer }}</p>

        <form method="POST" action="{{ url(config('nhs-login.mock.prefix').'/authorize') }}">
            <input type="hidden" name="client_id" value="{{ $field('client_id') }}">
            <input type="hidden" name="redirect_uri" value="{{ $field('redirect_uri') }}">
            <input type="hidden" name="state" value="{{ $field('state') }}">
            <input type="hidden" name="nonce" value="{{ $field('nonce') }}">
            <input type="hidden" name="scope" value="{{ $field('scope') }}">

            <fieldset>
                <legend>Identity</legend>
                <label for="vector">Vector of Trust</label>
                <select name="vector" id="vector">
                    @foreach ($requested as $vector)
                        <option value="{{ $vector }}">{{ $vector }} — requested</option>
                    @endforeach
                    @foreach ($others as $vector)
                        <option value="{{ $vector }}">{{ $vector }}</option>
                    @endforeach
                </select>
                <p class="meta" style="border:0;padding:0;margin:.5rem 0 0;">
                    Pick a level below the requested one to exercise your step-up path.
                    P0 returns no NHS number, name or date of birth.
                </p>
            </fieldset>

            <fieldset>
                <legend>Claims</legend>
                <div class="grid">
                    <div>
                        <label for="nhs_number">NHS number</label>
                        <input id="nhs_number" name="claims[nhs_number]" value="9912003888" autocomplete="off">
                    </div>
                    <div>
                        <label for="birthdate">Date of birth</label>
                        <input id="birthdate" name="claims[birthdate]" value="1980-04-01" autocomplete="off">
                    </div>
                    <div>
                        <label for="given_name">Given name</label>
                        <input id="given_name" name="claims[given_name]" value="Aisha" autocomplete="off">
                    </div>
                    <div>
                        <label for="family_name">Family name</label>
                        <input id="family_name" name="claims[family_name]" value="Khan" autocomplete="off">
                    </div>
                </div>
                <div class="row">
                    <label for="sub">Subject (leave blank for a new one)</label>
                    <input id="sub" name="claims[sub]" value="" placeholder="mock-…" autocomplete="off">
                </div>
            </fieldset>

            <div class="actions">
                <button type="submit" name="action" value="approve" class="primary">Sign in</button>
                <button type="submit" name="action" value="cancel" class="secondary">Cancel</button>
            </div>
        </form>

        <p class="meta">
            Scopes: <code>{{ $field('scope') ?: '(none)' }}</code><br>
            Returning to: <code>{{ $field('redirect_uri') }}</code>
            @unless ($hasNonce)
                <br><span class="warn">No nonce was sent — the client will reject the ID token.</span>
            @endunless
        </p>
    </div>
</body>
</html>
