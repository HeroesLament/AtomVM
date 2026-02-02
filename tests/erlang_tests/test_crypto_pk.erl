%
% This file is part of AtomVM.
%
% Copyright 2026 Davide Bettio <davide@uninstall.it>
%
% Licensed under the Apache License, Version 2.0 (the "License");
% you may not use this file except in compliance with the License.
% You may obtain a copy of the License at
%
%    http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS,
% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
% See the License for the specific language governing permissions and
% limitations under the License.
%
% SPDX-License-Identifier: Apache-2.0 OR LGPL-2.1-or-later
%

-module(test_crypto_pk).
-export([start/0, test_generate_and_compute_key/0, test_sign_and_verify/0,
         test_eddsa_sign_and_verify/0]).

start() ->
    ok = mbedtls_conditional_run(test_generate_and_compute_key, 16#03000000),
    ok = mbedtls_conditional_run(test_sign_and_verify, 16#03060100),
    ok = mbedtls_conditional_run(test_eddsa_sign_and_verify, 16#03060100),
    0.

mbedtls_conditional_run(F, RVer) ->
    Info = crypto:info_lib(),
    case find_openssl_or_mbedtls_ver(Info, RVer) of
        true ->
            ?MODULE:F();
        false ->
            erlang:display({skipped, ?MODULE, F}),
            ok
    end.

find_openssl_or_mbedtls_ver([], _RVer) ->
    false;
find_openssl_or_mbedtls_ver([{<<"OpenSSL">>, _, _} | _T], _RVer) ->
    true;
find_openssl_or_mbedtls_ver([{<<"mbedtls">>, Ver, _} | _T], RVer) when Ver >= RVer ->
    true;
find_openssl_or_mbedtls_ver([_ | T], RVer) ->
    find_openssl_or_mbedtls_ver(T, RVer).

test_generate_and_compute_key() ->
    {Pub, Priv} = crypto:generate_key(eddh, x25519),
    true = is_binary(Pub),
    32 = byte_size(Pub),
    true = is_binary(Priv),
    32 = byte_size(Priv),

    ComputedKey = crypto:compute_key(eddh, Pub, Priv, x25519),
    true = is_binary(ComputedKey),
    32 = byte_size(ComputedKey),

    {Pub2, Priv2} = crypto:generate_key(eddh, x25519),
    true = is_binary(Pub2),
    32 = byte_size(Pub2),
    true = is_binary(Priv2),
    32 = byte_size(Priv2),

    ComputedKey2 = crypto:compute_key(eddh, Pub2, Priv2, x25519),
    true = is_binary(ComputedKey2),
    32 = byte_size(ComputedKey2),

    ok.

test_sign_and_verify() ->
    Data = <<"Hello">>,

    %% ECDSA with secp256r1
    {SECPPub, SECPPriv} = crypto:generate_key(ecdh, secp256r1),
    Sig = crypto:sign(ecdsa, sha256, Data, [SECPPriv, secp256r1]),

    false = crypto:verify(ecdsa, sha256, <<"Invalid">>, Sig, [SECPPub, secp256r1]),
    false = crypto:verify(ecdsa, sha256, Data, <<"InvalidSig">>, [SECPPub, secp256r1]),
    true = crypto:verify(ecdsa, sha256, Data, Sig, [SECPPub, secp256r1]),

    %% EdDSA with Ed25519
    {EdPub, EdPriv} = crypto:generate_key(eddsa, ed25519),
    EdSig = crypto:sign(eddsa, none, Data, [EdPriv, ed25519]),
    64 = byte_size(EdSig),

    true = crypto:verify(eddsa, none, Data, EdSig, [EdPub, ed25519]),
    false = crypto:verify(eddsa, none, <<"Invalid">>, EdSig, [EdPub, ed25519]),

    ok.

test_eddsa_sign_and_verify() ->
    %% Key generation produces correct sizes
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    true = is_binary(Pub),
    32 = byte_size(Pub),
    true = is_binary(Priv),
    32 = byte_size(Priv),

    %% Sign empty message
    EmptySig = crypto:sign(eddsa, none, <<>>, [Priv, ed25519]),
    64 = byte_size(EmptySig),
    true = crypto:verify(eddsa, none, <<>>, EmptySig, [Pub, ed25519]),

    %% Sign non-trivial message
    Msg = <<"The quick brown fox jumps over the lazy dog">>,
    Sig = crypto:sign(eddsa, none, Msg, [Priv, ed25519]),
    64 = byte_size(Sig),
    true = crypto:verify(eddsa, none, Msg, Sig, [Pub, ed25519]),

    %% Wrong message fails verify
    false = crypto:verify(eddsa, none, <<"wrong">>, Sig, [Pub, ed25519]),

    %% Corrupted signature fails verify
    <<SigHead:8/binary, SigByte:8, SigTail/binary>> = Sig,
    Corrupted = <<SigHead/binary, (SigByte bxor 16#FF):8, SigTail/binary>>,
    64 = byte_size(Corrupted),
    false = crypto:verify(eddsa, none, Msg, Corrupted, [Pub, ed25519]),

    %% Signature from one key doesn't verify with another key
    {Pub2, Priv2} = crypto:generate_key(eddsa, ed25519),
    Sig2 = crypto:sign(eddsa, none, Msg, [Priv2, ed25519]),
    true = crypto:verify(eddsa, none, Msg, Sig2, [Pub2, ed25519]),
    false = crypto:verify(eddsa, none, Msg, Sig2, [Pub, ed25519]),
    false = crypto:verify(eddsa, none, Msg, Sig, [Pub2, ed25519]),

    %% Deterministic: same key + same message = same signature
    Sig3 = crypto:sign(eddsa, none, Msg, [Priv, ed25519]),
    true = (Sig =:= Sig3),

    ok.
