<?php

namespace Meness\Verifi;

use Carbon\Carbon;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Meness\Verifi\Entities\Traits\Contracts\Verifi as VerifiContract;
use Meness\Verifi\Events\InvalidCredentials;
use Meness\Verifi\Events\VerificationSent;
use Meness\Verifi\Events\Verified;
use UnexpectedValueException;

/**
 * Class Verifi
 * @package Meness\Verifi
 */
class Verifi {

    /**
     * Constant representing credentials are invalid.
     * @var string
     */
    const INVALID_CREDENTIALS = 'invalid';
    /**
     * The application key.
     * @var string
     */
    protected $appKey;
    /**
     * The event dispatcher instance.
     * @var \Illuminate\Events\Dispatcher
     */
    private $dispatcher;
    /**
     * The number of minutes that the reset token should be considered valid.
     * @var int
     */
    protected $expiration;
    /**
     * The user provider implementation.
     * @var \Illuminate\Contracts\Auth\UserProvider
     */
    protected $userProvider;

    /**
     * Create a new email verification instance.
     *
     * @param  \Illuminate\Contracts\Auth\UserProvider $userProvider
     * @param Dispatcher                               $dispatcher
     * @param  string                                  $appKey
     * @param  integer                                 $expiration
     */
    public function __construct(UserProvider $userProvider, Dispatcher $dispatcher, $appKey, $expiration) {

        $this->appKey       = $appKey;
        $this->userProvider = $userProvider;
        $this->expiration   = $expiration;
        $this->dispatcher   = $dispatcher;
    }

    /**
     * Send a email verification link to a user.
     *
     * @param \Meness\Verifi\Entities\Traits\Contracts\Verifi|\Illuminate\Notifications\Notifiable $user
     * @param null                                                                                 $callback
     *
     * @return mixed
     */
    public function resend($user, $callback = null) {

        $expiration = Carbon::now()->addMinutes($this->expiration)->timestamp;
        $token      = $this->createToken($user, $expiration);

        $user->sendEmailVerifyNotification($token, $expiration);

        $this->dispatcher->dispatch(new VerificationSent($user));

        return call_user_func($callback, $user);
    }

    /**
     * Create a new password reset token for the given user.
     *
     * @param  \Meness\Verifi\Entities\Traits\Contracts\Verifi $user
     * @param  integer                                         $expiration
     *
     * @return string
     */
    protected function createToken(VerifiContract $user, $expiration) {

        $payload = $this->buildPayload($user, $user->getEmailForEmailVerify(), $expiration);

        return hash_hmac('sha256', $payload, $this->getAppKey());
    }

    /**
     * Returns the payload string containing.
     *
     * @param \Meness\Verifi\Entities\Traits\Contracts\Verifi $user
     * @param  string                                         $email
     * @param  integer                                        $expiration
     *
     * @return string
     */
    protected function buildPayload(VerifiContract $user, $email, $expiration) {

        return implode(';', [
            $email,
            $expiration,
            $user->getPassword(),
        ]);
    }

    /**
     * Return the application key.
     * @return string
     */
    protected function getAppKey() {

        if (Str::startsWith($this->appKey, 'base64:')) {
            return base64_decode(substr($this->appKey, 7));
        }

        return $this->appKey;
    }

    /**
     * @param \Illuminate\Http\Request $request
     * @param null                     $callback
     *
     * @return mixed
     */
    public function verify($request, $callback = null) {

        $data = $request->only('token', 'email', 'expiration');

        /**
         * @var \Illuminate\Validation\Validator $validator
         */
        $validator = validator($data, [
            'token'      => 'required|string',
            'email'      => 'required|email',
            'expiration' => 'required|date_format:U',
        ]);

        if ($validator->fails()) {
            // Dispatch the invalid credentials event
            $this->dispatcher->dispatch(new InvalidCredentials($validator));

            $validator->validate();
        }

        list('token' => $token, 'email' => $email, 'expiration' => $expiration) = $data;

        $user = $this->validateCredentials($token, $email, $expiration);

        if (is_string($user)) {
            // Dispatch the invalid credentials event
            $this->dispatcher->dispatch(new InvalidCredentials(null));

            return call_user_func($callback, null);
        }

        // Dispatch the verified event
        $this->dispatcher->dispatch(new Verified($user));

        return $callback != null ? call_user_func($callback, $user) :null;
    }

    /**
     * Validate a email verification for the given credentials.
     *
     * @param $token
     * @param $email
     * @param $expiration
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|string
     */
    protected function validateCredentials($token, $email, $expiration) {

        if (is_null($user = $this->validateEmail($email)) || !$this->validateToken($user, $token, $email, $expiration) || !$this->validateTimestamp($expiration)) {
            return self::INVALID_CREDENTIALS;
        }

        return $user;
    }

    /**
     * Get the user for the given credentials.
     *
     * @param $email
     *
     * @return \Meness\Verifi\Entities\Traits\Contracts\Verifi|null
     * @throws \UnexpectedValueException
     */
    protected function validateEmail($email) {

        $user = $this->userProvider->retrieveByCredentials(Arr::add([], 'email', $email));
        if ($user && !$user instanceof VerifiContract) {
            throw new UnexpectedValueException('User model must implement Traits\Contracts\Verifi interface.');
        }

        return $user;
    }

    /**
     * Validate the given password reset token.
     *
     * @param Entities\Traits\Contracts\Verifi $user
     * @param string                           $token
     * @param string                           $email
     * @param integer                          $expiration
     *
     * @return bool
     */
    protected function validateToken(VerifiContract $user, $token, $email, $expiration) {

        $payload = $this->buildPayload($user, $email, $expiration);

        return hash_equals($token, hash_hmac('sha256', $payload, $this->getAppKey()));
    }

    /**
     * Validate the given expiration timestamp.
     *
     * @param  integer $expiration
     *
     * @return bool
     */
    protected function validateTimestamp($expiration) {

        return Carbon::createFromTimestamp($expiration)->isFuture();
    }
}