<?php

namespace Meness\Verifi\Http\Middleware;

use Closure;
use Meness\Verifi\Exceptions\UserNotVerifiedException;

/**
 * Class IsEmailVerified
 * @package Meness\Verifi\Http\Middleware
 */
class IsEmailVerified {

    /**
     * @param \Illuminate\Http\Request $request
     * @param Closure                  $next
     *
     * @return mixed
     * @throws \Meness\Verifi\Exceptions\UserNotVerifiedException
     */
    public function handle($request, Closure $next) {

        if (!is_null($request->user()) && !$request->user()->isEmailVerified()) {
            throw new UserNotVerifiedException();
        }

        return $next($request);
    }
}
