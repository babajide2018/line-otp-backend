<?php

namespace App\Http\Controllers;

use GNOffice\OAuth2\Client\Provider\Line;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    //



    public function redirectToLine(Request $request)
    {



        $clientId = env('LINE_LOGIN_CLIENT_ID');
        $clientSecret = env('LINE_LOGIN_CLIENT_SECRET');
        $redirectUri = env('LINE_LOGIN_REDIRECT_URI');

        $line = new Line([
            'clientId' => $clientId,
            'clientSecret' => $clientSecret,
            'redirectUri' => $redirectUri,
        ]);

        $authorizationUrl = $line->getAuthorizationUrl();

        if ($request->expectsJson()) {
            // If the request expects JSON, return a JSON response
            return new JsonResponse(['authorization_url' => $authorizationUrl]);
        }

        // Otherwise, perform a regular redirect
        return redirect($authorizationUrl);
    }


    public function handleLineCallback(Request $request)
    {
        $clientId = env('LINE_LOGIN_CLIENT_ID');
        $clientSecret = env('LINE_LOGIN_CLIENT_SECRET');
        $redirectUri = env('LINE_LOGIN_REDIRECT_URI');
    
        $line = new Line([
            'clientId' => $clientId,
            'clientSecret' => $clientSecret,
            'redirectUri' => $redirectUri,
        ]);
    
        try {
            // Get access token
            $accessToken = $line->getAccessToken('authorization_code', [
                'code' => $request->get('code'),
                'nonce' => $request->session()->get('oauth2nonce'),
            ]);
    
            // Get user details
            $user = $line->getResourceOwner($accessToken);
    
            // Extract user details from the response array
            $userId = $user->getId();
            $details = $user->toArray();
    
            // Generate a random OTP
            $otp = rand(1000, 9999);
    
            // Cache the OTP with the user ID for verification with a 30-second expiration
            Cache::put('otp_' . $userId, $otp, now()->addSeconds(30));
    
            // Redirect back to React app with user details and OTP as query parameters
            return redirect('http://localhost:3000/?userId=' . $userId . '&displayName=' . $details['displayName'] . '&pictureUrl=' . $details['pictureUrl'] . '&otp=' . $otp);
        } catch (IdentityProviderException $e) {
            // Handle errors appropriately
            return response()->json(['error' => 'Login failed'], 400);
        }
    }


}
