<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    public function daftar(Request $request) {
        try {
            // Validasi data
            $validated = $request->validate([
                'nama'      => 'required|string|max:255',
                'email'     => 'required|string|email|unique:users,email',
                'sandi'     => 'required|string|min:8'
            ]);

            // Buat data user
            User::create([
                'name'      => Str::lower($validated['nama']),
                'email'     => $validated['email'],
                'password'  => $validated['sandi'],
            ]);

            // Kembalikan data
            return response()->json([
                'message'   => 'Pendaftaran berhasil',
            ], 201);

        } catch (ValidationException $ve) {
            return response()->json([
                'message'   => 'Validasi gagal!',
                'error'     => $ve->errors()
            ], 422);
        } catch (\Throwable $th) {
            return response()->json([
                'message'   => 'Tidak dapat memproses data',
                'error'     => $th->getMessage() 
            ], 500);
        }
    }

    public function masuk(Request $request)
    {
        try {
            // Validasi data
            $validated = $request->validate([
                'email'     => 'required|string|email',
                'sandi'     => 'required|string|min:8'
            ]);

            // Cari user berdasarkan email
            $user = User::where('email', $validated['email'])->first();

            // Cek kata sandi
            if (!$user || !Hash::check($validated['sandi'], $user->password)) {
                return response()->json([
                    'message' => 'Email atau kata sandi salah!',
                ], 401);
            }

            // Buat token
            $token = $user->createToken('auth-token')->plainTextToken;

            // Kembalikan data
            return response()->json([
                'message' => 'Login berhasil',
                'data' => [
                    'user' => [
                        'id' => $user->id,
                        'name' => $user->name,
                        'email' => $user->email,
                    ],
                    'token' => $token,
                    'token_type' => 'Bearer',
                ],
            ], 200);

        } catch (ValidationException $ve) {
            return response()->json([
                'message' => 'Validasi gagal!',
                'errors'  => $ve->errors(),
            ], 422);

        } catch (\Throwable $th) {
            return response()->json([
                'message'   => 'Tidak dapat memproses data',
                'error'     => $th->getMessage() 
            ], 500);
        }
    }
}
