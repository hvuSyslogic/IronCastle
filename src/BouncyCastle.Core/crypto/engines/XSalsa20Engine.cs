﻿using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.engines
{
	
	/// <summary>
	/// Implementation of Daniel J. Bernstein's XSalsa20 stream cipher - Salsa20 with an extended nonce.
	/// <para>
	/// XSalsa20 requires a 256 bit key, and a 192 bit nonce.
	/// </para>
	/// </summary>
	public class XSalsa20Engine : Salsa20Engine
	{
		public override string getAlgorithmName()
		{
			return "XSalsa20";
		}

		public override int getNonceSize()
		{
			return 24;
		}

		/// <summary>
		/// XSalsa20 key generation: process 256 bit input key and 128 bits of the input nonce
		/// using a core Salsa20 function without input addition to produce 256 bit working key
		/// and use that with the remaining 64 bits of nonce to initialize a standard Salsa20 engine state.
		/// </summary>
		public override void setKey(byte[] keyBytes, byte[] ivBytes)
		{
			if (keyBytes == null)
			{
				throw new IllegalArgumentException(getAlgorithmName() + " doesn't support re-init with null key");
			}

			if (keyBytes.Length != 32)
			{
				throw new IllegalArgumentException(getAlgorithmName() + " requires a 256 bit key");
			}

			// Set key for HSalsa20
			base.setKey(keyBytes, ivBytes);

			// Pack next 64 bits of IV into engine state instead of counter
			Pack.littleEndianToInt(ivBytes, 8, engineState, 8, 2);

			// Process engine state to generate Salsa20 key
			int[] hsalsa20Out = new int[engineState.Length];
			salsaCore(20, engineState, hsalsa20Out);

			// Set new key, removing addition in last round of salsaCore
			engineState[1] = hsalsa20Out[0] - engineState[0];
			engineState[2] = hsalsa20Out[5] - engineState[5];
			engineState[3] = hsalsa20Out[10] - engineState[10];
			engineState[4] = hsalsa20Out[15] - engineState[15];

			engineState[11] = hsalsa20Out[6] - engineState[6];
			engineState[12] = hsalsa20Out[7] - engineState[7];
			engineState[13] = hsalsa20Out[8] - engineState[8];
			engineState[14] = hsalsa20Out[9] - engineState[9];

			// Last 64 bits of input IV
			Pack.littleEndianToInt(ivBytes, 16, engineState, 6, 2);
		}
	}

}