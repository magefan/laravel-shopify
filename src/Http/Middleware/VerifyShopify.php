<?php

namespace Osiset\ShopifyApp\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Osiset\ShopifyApp\Contracts\ApiHelper as IApiHelper;
use Osiset\ShopifyApp\Exceptions\SignatureVerificationException;
use Osiset\ShopifyApp\Objects\Enums\DataSource;

/**
 * Responsible for validating the request.
 */
class VerifyShopify
{

    /**
     * The API helper.
     *
     * @var IApiHelper
     */
    protected $apiHelper;

    public function handle(Request $request, Closure $next)
    {
        // Verify the HMAC (if available)
        $hmacResult = $this->verifyHmac($request);
        if ($hmacResult === false) {
            // Invalid HMAC
            throw new SignatureVerificationException('Unable to verify signature.');
        }

        return $next($request);
    }

    /**
     * Verify HMAC data, if present.
     *
     * @param Request $request The request object.
     *
     * @throws SignatureVerificationException
     *
     * @return bool|null
     */
    protected function verifyHmac(Request $request): ?bool
    {
        $hmac = $this->getHmacFromRequest($request);
        if ($hmac['source'] === null) {
            // No HMAC, skip
            return null;
        }

        // We have HMAC, validate it
        $data = $this->getRequestData($request, $hmac['source']);

        return $this->apiHelper->verifyRequest($data);
    }

    /**
     * Login and verify the shop and it's data.
     *
     * @param SessionToken      $token     The session token.
     * @param NullableSessionId $sessionId Incoming session ID (if available).
     *
     * @return bool
     */
    protected function loginShopFromToken(SessionToken $token, NullableSessionId $sessionId): bool
    {
        // Get the shop
        $shop = $this->shopQuery->getByDomain($token->getShopDomain(), [], true);
        if (! $shop) {
            return false;
        }

        // Set the session details for the token, session ID, and access token
        $context = new SessionContext($token, $sessionId, $shop->getAccessToken());
        $shop->setSessionContext($context);

        $previousContext = $this->previousShop ? $this->previousShop->getSessionContext() : null;
        if (! $shop->getSessionContext()->isValid($previousContext)) {
            // Something is invalid
            return false;
        }

        // Override auth guard
        if (($guard = Util::getShopifyConfig('shop_auth_guard'))) {
            $this->auth->setDefaultDriver($guard);
        }

        // All is well, login the shop
        $this->auth->login($shop);

        return true;
    }

    /**
     * Redirect to token route.
     *
     * @param Request $request The request object.
     *
     * @return RedirectResponse
     */
    protected function tokenRedirect(Request $request): RedirectResponse
    {
        // At this point the HMAC and other details are verified already, filter it out
        $path = $request->path();
        $target = Str::start($path, '/');

        if ($request->query()) {
            $filteredQuery = Collection::make($request->query())->except([
                'hmac',
                'locale',
                'new_design_language',
                'timestamp',
                'session',
                'shop',
            ]);

            if ($filteredQuery->isNotEmpty()) {
                $target .= '?'.http_build_query($filteredQuery->toArray());
            }
        }

        return Redirect::route(
            Util::getShopifyConfig('route_names.authenticate.token'),
            [
                'shop' => ShopDomain::fromRequest($request)->toNative(),
                'target' => $target,
            ]
        );
    }

    /**
     * Redirect to install route.
     *
     * @param ShopDomainValue $shopDomain The shop domain.
     *
     * @return RedirectResponse
     */
    protected function installRedirect(ShopDomainValue $shopDomain): RedirectResponse
    {
        return Redirect::route(
            Util::getShopifyConfig('route_names.authenticate'),
            ['shop' => $shopDomain->toNative()]
        );
    }

    /**
     * Grab the HMAC value, if present, and how it was found.
     * Order of precedence is:.
     *
     *  - GET/POST Variable
     *  - Headers
     *  - Referer
     *
     * @param Request $request The request object.
     *
     * @return array
     */
    protected function getHmacFromRequest(Request $request): array
    {
        // All possible methods
        $options = [
            // GET/POST
            DataSource::INPUT()->toNative() => $request->input('hmac'),
            // Headers
            DataSource::HEADER()->toNative() => $request->header('X-Shop-Signature'),
            // Headers: Referer
            DataSource::REFERER()->toNative() => function () use ($request): ?string {
                $url = parse_url($request->header('referer'), PHP_URL_QUERY);
                parse_str($url, $refererQueryParams);
                if (! $refererQueryParams || ! isset($refererQueryParams['hmac'])) {
                    return null;
                }

                return $refererQueryParams['hmac'];
            },
        ];

        // Loop through each until we find the HMAC
        foreach ($options as $method => $value) {
            $result = is_callable($value) ? $value() : $value;
            if ($result !== null) {
                return ['source' => $method, 'value' => $value];
            }
        }

        return ['source' => null, 'value' => null];
    }

    /**
     * Grab the request data.
     *
     * @param Request $request The request object.
     * @param string  $source  The source of the data.
     *
     * @return array
     */
    protected function getRequestData(Request $request, string $source): array
    {
        // All possible methods
        $options = [
            // GET/POST
            DataSource::INPUT()->toNative() => function () use ($request): array {
                // Verify
                $verify = [];
                foreach ($request->query() as $key => $value) {
                    $verify[$key] = $this->parseDataSourceValue($value);
                }

                return $verify;
            },
            // Headers
            DataSource::HEADER()->toNative() => function () use ($request): array {
                // Always present
                $shop = $request->header('X-Shop-Domain');
                $signature = $request->header('X-Shop-Signature');
                $timestamp = $request->header('X-Shop-Time');

                $verify = [
                    'shop' => $shop,
                    'hmac' => $signature,
                    'timestamp' => $timestamp,
                ];

                // Sometimes present
                $code = $request->header('X-Shop-Code') ?? null;
                $locale = $request->header('X-Shop-Locale') ?? null;
                $state = $request->header('X-Shop-State') ?? null;
                $id = $request->header('X-Shop-ID') ?? null;
                $ids = $request->header('X-Shop-IDs') ?? null;

                foreach (compact('code', 'locale', 'state', 'id', 'ids') as $key => $value) {
                    if ($value) {
                        $verify[$key] = $this->parseDataSourceValue($value);
                    }
                }

                return $verify;
            },
            // Headers: Referer
            DataSource::REFERER()->toNative() => function () use ($request): array {
                $url = parse_url($request->header('referer'), PHP_URL_QUERY);
                parse_str($url, $refererQueryParams);

                // Verify
                $verify = [];
                foreach ($refererQueryParams as $key => $value) {
                    $verify[$key] = $this->parseDataSourceValue($value);
                }

                return $verify;
            },
        ];

        return $options[$source]();
    }


    /**
     * Parse the data source value.
     * Handle simple key/values, arrays, and nested arrays.
     *
     * @param mixed $value
     *
     * @return string
     */
    protected function parseDataSourceValue($value): string
    {
        /**
         * Format the value.
         *
         * @param mixed $val
         *
         * @return string
         */
        $formatValue = function ($val): string {
            return is_array($val) ? '["'.implode('", "', $val).'"]' : $val;
        };

        // Nested array
        if (is_array($value) && is_array(current($value))) {
            return implode(', ', array_map($formatValue, $value));
        }

        // Array or basic value
        return $formatValue($value);
    }

    /**
     * Determine if the request is AJAX or expects JSON.
     *
     * @param Request $request The request object.
     *
     * @return bool
     */
    protected function isApiRequest(Request $request): bool
    {
        return $request->ajax() || $request->expectsJson();
    }

    /**
     * Check if there is a store record in the database.
     *
     * @param Request $request The request object.
     *
     * @return bool
     */
    protected function checkPreviousInstallation(Request $request): bool
    {
        $shop = $this->shopQuery->getByDomain(ShopDomain::fromRequest($request), [], true);

        return $shop && $shop->password && ! $shop->trashed();
    }

}
