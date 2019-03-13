<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

use App\User;
use JWTAuth;
use JWTAuthExceptions;

class AutController extends Controller
{
    // public  function __construct()
    // {
    //     $this->middleware('jwt.auth');
    // }

    public function store(Request $request)
    {
        $this->validate($request, [
            'name' => ['required'],
            'email' => ['required', 'email'],
            'password' => ['required'],
        ]);

        $name = $request->input('name');
        $email = $request->input('email');
        $password = $request->input('password');

        $user = new User([
            'name' => $name,
            'email' => $email,
            'password' => bcrypt($password),
        ]);

        $crentials = [
            'email' => $email,
            'password' => $password
        ];

        if ($user->save()) {

            $token = null;
            try {
                if(!$token = JWTAuth::attempt($crentials)){
                    return response()->json([
                        'msg' => 'Email or Password Inccorect'
                    ], 404);
                }
            } catch (JWTAuthException $e) {
                return response()->json([
                    'msg' => 'Failde to create_token'
                ], 400);

            }

            $user->signin = [
                'href' => 'api/v1/user/signin',
                'method' => 'POST',
                'params' => 'email, password',
            ];

            $response = [
                'msg' => 'User created',
                'user' => $user,
                'token' => $token,
            ];

            return response()->json($response, 201);
        }

    }

    public function signin(Request $request )
    {
        $this->validate($request, [
            'email' => ['required', 'email'],
            'password' => ['required']
        ]);

        $email = $request->input('email');
        $password = $request->input('password');

        if ($user = User::where('email', $email)->first()) {
            $crentials = [
                'email' => $email,
                'password' => $password,
            ];


            $token = null;
            try {
                if(!$token = JWTAuth::attempt($crentials)){
                    return response()->json([
                        'msg' => 'Email and Password are Inccorect'
                    ], 404);
                }
            } catch (JWTAuthException $e) {
                return response()->json([
                    'msg' => 'Failde to create_token'
                ], 404);
            }


            $response = [
                'msg' => 'User Signin',
                'user' => $user,
                'token' => $token,
            ];

            return response()->json($response, 201);
        }

        $response = [
            'msg' => 'An Error Occured'
        ];

        return response()->json($response, 404);
    }
}
