﻿using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
	
	/// <summary>
	/// A Noekeon engine, using direct-key mode.
	/// </summary>

	public class NoekeonEngine : BlockCipher
	{
		private const int genericSize = 16; // Block and key size, as well as the amount of rounds.

		private static readonly int[] nullVector = new int[] {0x00, 0x00, 0x00, 0x00}, roundConstants = new int[] {0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4};

		private int[] state = new int[4], subKeys = new int[4], decryptKeys = new int[4];

		private bool _initialised, _forEncryption;

		/// <summary>
		/// Create an instance of the Noekeon encryption algorithm
		/// and set some defaults
		/// </summary>
		public NoekeonEngine()
		{
			_initialised = false;
		}

		public virtual string getAlgorithmName()
		{
			return "Noekeon";
		}

		public virtual int getBlockSize()
		{
			return genericSize;
		}

		/// <summary>
		/// initialise
		/// </summary>
		/// <param name="forEncryption"> whether or not we are for encryption. </param>
		/// <param name="params"> the parameters required to set up the cipher. </param>
		/// <exception cref="IllegalArgumentException"> if the params argument is
		/// inappropriate. </exception>
		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			if (!(@params is KeyParameter))
			{
				throw new IllegalArgumentException("invalid parameter passed to Noekeon init - " + @params.GetType().getName());
			}

			_forEncryption = forEncryption;
			_initialised = true;

			KeyParameter p = (KeyParameter)@params;

			setKey(p.getKey());
		}

		public virtual int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			if (!_initialised)
			{
				throw new IllegalStateException(getAlgorithmName() + " not initialised");
			}

			if ((inOff + genericSize) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			if ((outOff + genericSize) > @out.Length)
			{
				throw new OutputLengthException("output buffer too short");
			}

			return (_forEncryption) ? encryptBlock(@in, inOff, @out, outOff) : decryptBlock(@in, inOff, @out, outOff);
		}

		public virtual void reset()
		{
		}

		/// <summary>
		/// Re-key the cipher.
		/// <para>
		/// </para>
		/// </summary>
		/// <param name="key">  the key to be used </param>
		private void setKey(byte[] key)
		{
			subKeys[0] = bytesToIntBig(key, 0);
			subKeys[1] = bytesToIntBig(key, 4);
			subKeys[2] = bytesToIntBig(key, 8);
			subKeys[3] = bytesToIntBig(key, 12);
		}

		private int encryptBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			state[0] = bytesToIntBig(@in, inOff);
			state[1] = bytesToIntBig(@in, inOff + 4);
			state[2] = bytesToIntBig(@in, inOff + 8);
			state[3] = bytesToIntBig(@in, inOff + 12);

			int i;
			for (i = 0; i < genericSize; i++)
			{
				state[0] ^= roundConstants[i];
				theta(state, subKeys);
				pi1(state);
				gamma(state);
				pi2(state);
			}

			state[0] ^= roundConstants[i];
			theta(state, subKeys);

			intToBytesBig(state[0], @out, outOff);
			intToBytesBig(state[1], @out, outOff + 4);
			intToBytesBig(state[2], @out, outOff + 8);
			intToBytesBig(state[3], @out, outOff + 12);

			return genericSize;
		}

		private int decryptBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			state[0] = bytesToIntBig(@in, inOff);
			state[1] = bytesToIntBig(@in, inOff + 4);
			state[2] = bytesToIntBig(@in, inOff + 8);
			state[3] = bytesToIntBig(@in, inOff + 12);

			JavaSystem.arraycopy(subKeys, 0, decryptKeys, 0, subKeys.Length);
			theta(decryptKeys, nullVector);

			int i;
			for (i = genericSize; i > 0; i--)
			{
				theta(state, decryptKeys);
				state[0] ^= roundConstants[i];
				pi1(state);
				gamma(state);
				pi2(state);
			}

			theta(state, decryptKeys);
			state[0] ^= roundConstants[i];

			intToBytesBig(state[0], @out, outOff);
			intToBytesBig(state[1], @out, outOff + 4);
			intToBytesBig(state[2], @out, outOff + 8);
			intToBytesBig(state[3], @out, outOff + 12);

			return genericSize;
		}

		private void gamma(int[] a)
		{
			a[1] ^= ~a[3] & ~a[2];
			a[0] ^= a[2] & a[1];

			int tmp = a[3];
			a[3] = a[0];
			a[0] = tmp;
			a[2] ^= a[0] ^ a[1] ^ a[3];

			a[1] ^= ~a[3] & ~a[2];
			a[0] ^= a[2] & a[1];
		}

		private void theta(int[] a, int[] k)
		{
			int tmp;

			tmp = a[0] ^ a[2];
			tmp ^= rotl(tmp,8) ^ rotl(tmp,24);
			a[1] ^= tmp;
			a[3] ^= tmp;

			for (int i = 0; i < 4; i++)
			{
				a[i] ^= k[i];
			}

			tmp = a[1] ^ a[3];
			tmp ^= rotl(tmp,8) ^ rotl(tmp,24);
			a[0] ^= tmp;
			a[2] ^= tmp;
		}

		private void pi1(int[] a)
		{
			a[1] = rotl(a[1], 1);
			a[2] = rotl(a[2], 5);
			a[3] = rotl(a[3], 2);
		}

		private void pi2(int[] a)
		{
			a[1] = rotl(a[1], 31);
			a[2] = rotl(a[2], 27);
			a[3] = rotl(a[3], 30);
		}

		// Helpers

		private int bytesToIntBig(byte[] @in, int off)
		{
			return ((@in[off++]) << 24) | ((@in[off++] & 0xff) << 16) | ((@in[off++] & 0xff) << 8) | (@in[off] & 0xff);
		}

		private void intToBytesBig(int x, byte[] @out, int off)
		{
			@out[off++] = (byte)((int)((uint)x >> 24));
			@out[off++] = (byte)((int)((uint)x >> 16));
			@out[off++] = (byte)((int)((uint)x >> 8));
			@out[off] = (byte)x;
		}

		private int rotl(int x, int y)
		{
			return (x << y) | ((int)((uint)x >> (32 - y)));
		}
	}

}