<?php

namespace AppBundle\Security;

use AppBundle\Entity\User;
use KnpU\OAuth2ClientBundle\Security\Exception\FinishRegistrationException;
use KnpU\OAuth2ClientBundle\Security\Helper\FinishRegistrationBehavior;
use Doctrine\ORM\EntityManager;
use KnpU\OAuth2ClientBundle\Security\Helper\PreviousUrlHelper;
use KnpU\OAuth2ClientBundle\Security\Helper\SaveAuthFailureMessage;
use League\OAuth2\Client\Provider\Facebook;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Routing\RouterInterface;
use KnpU\OAuth2ClientBundle\Security\Authenticator\SocialAuthenticator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use KnpU\OAuth2ClientBundle\Client\Provider\FacebookClient;

class FacebookAuthenticator extends SocialAuthenticator
{
    use PreviousUrlHelper;
    use SaveAuthFailureMessage;
    use FinishRegistrationBehavior;

    /**
     * @var Facebook
     */
    private $facebookClient;
    /**
     * @var EntityManager
     */
    private $em;
    /**
     * @var RouterInterface
     */
    private $router;

    public function __construct(FacebookClient $facebookClient, EntityManager $em, RouterInterface $router)
    {
        $this->facebookClient = $facebookClient;
        $this->em = $em;
        $this->router = $router;
    }

    public function getCredentials(Request $request)
    {
        if ($request->getPathInfo() != '/connect/facebook-check') {
            // don't auth
            return;
        }

        return $this->fetchAccessToken($this->getFacebookClient());
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        /** @var FacebookUser $facebookUser */
        $facebookUser = $this->getFacebookClient()
            ->fetchUserFromToken($credentials);

        $email = $facebookUser->getEmail();

        // 1) have they logged in with Facebook before? Easy!
        $existingUser = $this->em->getRepository('AppBundle:User')
            ->findOneBy(array('facebookId' => $facebookUser->getId()));
        if ($existingUser) {
            return $existingUser;
        }

        // 2) do we have a matching user by email?
        $user = $this->em->getRepository('AppBundle:User')
                    ->findOneBy(array('email' => $email));

        // 3) Maybe you just want to "register" them by creating
        // a User object
        $user->setFacebookId($facebookUser->getId());
        $this->em->persist($user);
        $this->em->flush();

        return $user;
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        return true;
        // do nothing - the fact that the access token worked means that
        // our app has been authorized with Facebook
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        if ($exception instanceof FinishRegistrationException) {
            $this->saveUserInfoToSession($request, $exception);

            $registrationUrl = $this->router->generate('connect_facebook_registration');

            return new RedirectResponse($registrationUrl);
        }

        $this->saveAuthenticationErrorToSession($request, $exception);

        $loginUrl = $this->router->generate('security_login');

        return new RedirectResponse($loginUrl);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        if (!$url = $this->getPreviousUrl($request, $providerKey)) {
            $url = $this->router->generate('homepage');
        }

        return new RedirectResponse($url);
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
        // not called in our app, but if it were, redirecting to the
        // login page makes sense
        $url = $this->router
            ->generate('security_login');

        return new RedirectResponse($url);
    }
}
