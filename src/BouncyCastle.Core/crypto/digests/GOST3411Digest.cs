using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.digests
{
	using GOST28147Engine = org.bouncycastle.crypto.engines.GOST28147Engine;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithSBox = org.bouncycastle.crypto.@params.ParametersWithSBox;
	using Arrays = org.bouncycastle.util.Arrays;
	using Memoable = org.bouncycastle.util.Memoable;
	using Pack = org.bouncycastle.util.Pack;

	/// <summary>
	/// implementation of GOST R 34.11-94
	/// </summary>
	public class GOST3411Digest : ExtendedDigest, Memoable
	{
		private const int DIGEST_LENGTH = 32;

		private byte[] H = new byte[32], L = new byte[32], M = new byte[32], Sum = new byte[32];
//JAVA TO C# CONVERTER NOTE: The following call to the 'RectangularArrays' helper class reproduces the rectangular array initialization that is automatic in Java:
//ORIGINAL LINE: private byte[][] C = new byte[4][32];
		private byte[][] C = RectangularArrays.ReturnRectangularSbyteArray(4, 32);

		private byte[] xBuf = new byte[32];
		private int xBufOff;
		private long byteCount;

		private BlockCipher cipher = new GOST28147Engine();
		private byte[] sBox;

		/// <summary>
		/// Standard constructor
		/// </summary>
		public GOST3411Digest()
		{
			sBox = GOST28147Engine.getSBox("D-A");
			cipher.init(true, new ParametersWithSBox(null, sBox));

			reset();
		}

		/// <summary>
		/// Constructor to allow use of a particular sbox with GOST28147 </summary>
		/// <seealso cref= GOST28147Engine#getSBox(String) </seealso>
		public GOST3411Digest(byte[] sBoxParam)
		{
			sBox = Arrays.clone(sBoxParam);
			cipher.init(true, new ParametersWithSBox(null, sBox));

			reset();
		}

		/// <summary>
		/// Copy constructor.  This will copy the state of the provided
		/// message digest.
		/// </summary>
		public GOST3411Digest(GOST3411Digest t)
		{
			reset(t);
		}

		public virtual string getAlgorithmName()
		{
			return "GOST3411";
		}

		public virtual int getDigestSize()
		{
			return DIGEST_LENGTH;
		}

		public virtual void update(byte @in)
		{
			xBuf[xBufOff++] = @in;
			if (xBufOff == xBuf.Length)
			{
				sumByteArray(xBuf); // calc sum M
				processBlock(xBuf, 0);
				xBufOff = 0;
			}
			byteCount++;
		}

		public virtual void update(byte[] @in, int inOff, int len)
		{
			while ((xBufOff != 0) && (len > 0))
			{
				update(@in[inOff]);
				inOff++;
				len--;
			}

			while (len > xBuf.Length)
			{
				JavaSystem.arraycopy(@in, inOff, xBuf, 0, xBuf.Length);

				sumByteArray(xBuf); // calc sum M
				processBlock(xBuf, 0);
				inOff += xBuf.Length;
				len -= xBuf.Length;
				byteCount += xBuf.Length;
			}

			// load in the remainder.
			while (len > 0)
			{
				update(@in[inOff]);
				inOff++;
				len--;
			}
		}

		// (i + 1 + 4(k - 1)) = 8i + k      i = 0-3, k = 1-8
		private byte[] K = new byte[32];

		private byte[] P(byte[] @in)
		{
			for (int k = 0; k < 8; k++)
			{
				K[4 * k] = @in[k];
				K[1 + 4 * k] = @in[8 + k];
				K[2 + 4 * k] = @in[16 + k];
				K[3 + 4 * k] = @in[24 + k];
			}

			return K;
		}

		//A (x) = (x0 ^ x1) || x3 || x2 || x1
		internal byte[] a = new byte[8];
		private byte[] A(byte[] @in)
		{
			for (int j = 0; j < 8; j++)
			{
				a[j] = (byte)(@in[j] ^ @in[j + 8]);
			}

			JavaSystem.arraycopy(@in, 8, @in, 0, 24);
			JavaSystem.arraycopy(a, 0, @in, 24, 8);

			return @in;
		}

		//Encrypt function, ECB mode
		private void E(byte[] key, byte[] s, int sOff, byte[] @in, int inOff)
		{
			cipher.init(true, new KeyParameter(key));

			cipher.processBlock(@in, inOff, s, sOff);
		}

		// (in:) n16||..||n1 ==> (out:) n1^n2^n3^n4^n13^n16||n16||..||n2
		internal short[] wS = new short[16], w_S = new short[16];

		private void fw(byte[] @in)
		{
			cpyBytesToShort(@in, wS);
			w_S[15] = (short)(wS[0] ^ wS[1] ^ wS[2] ^ wS[3] ^ wS[12] ^ wS[15]);
			JavaSystem.arraycopy(wS, 1, w_S, 0, 15);
			cpyShortToBytes(w_S, @in);
		}

		// block processing
		internal byte[] S = new byte[32];
		internal byte[] U = new byte[32], V = new byte[32], W = new byte[32];

		public virtual void processBlock(byte[] @in, int inOff)
		{
			JavaSystem.arraycopy(@in, inOff, M, 0, 32);

			//key step 1

			// H = h3 || h2 || h1 || h0
			// S = s3 || s2 || s1 || s0
			JavaSystem.arraycopy(H, 0, U, 0, 32);
			JavaSystem.arraycopy(M, 0, V, 0, 32);
			for (int j = 0; j < 32; j++)
			{
				W[j] = (byte)(U[j] ^ V[j]);
			}
			// Encrypt gost28147-ECB
			E(P(W), S, 0, H, 0); // s0 = EK0 [h0]

			//keys step 2,3,4
			for (int i = 1; i < 4; i++)
			{
				byte[] tmpA = A(U);
				for (int j = 0; j < 32; j++)
				{
					U[j] = (byte)(tmpA[j] ^ C[i][j]);
				}
				V = A(A(V));
				for (int j = 0; j < 32; j++)
				{
					W[j] = (byte)(U[j] ^ V[j]);
				}
				// Encrypt gost28147-ECB
				E(P(W), S, i * 8, H, i * 8); // si = EKi [hi]
			}

			// x(M, H) = y61(H^y(M^y12(S)))
			for (int n = 0; n < 12; n++)
			{
				fw(S);
			}
			for (int n = 0; n < 32; n++)
			{
				S[n] = (byte)(S[n] ^ M[n]);
			}

			fw(S);

			for (int n = 0; n < 32; n++)
			{
				S[n] = (byte)(H[n] ^ S[n]);
			}
			for (int n = 0; n < 61; n++)
			{
				fw(S);
			}
			JavaSystem.arraycopy(S, 0, H, 0, H.Length);
		}

		private void finish()
		{
			Pack.longToLittleEndian(byteCount * 8, L, 0); // get length into L (byteCount * 8 = bitCount)

			while (xBufOff != 0)
			{
				update((byte)0);
			}

			processBlock(L, 0);
			processBlock(Sum, 0);
		}

		public virtual int doFinal(byte[] @out, int outOff)
		{
			finish();

			JavaSystem.arraycopy(H, 0, @out, outOff, H.Length);

			reset();

			return DIGEST_LENGTH;
		}

		/// <summary>
		/// reset the chaining variables to the IV values.
		/// </summary>
		private static readonly byte[] C2 = new byte[] {0x00, unchecked((byte)0xFF), 0x00, unchecked((byte)0xFF), 0x00, unchecked((byte)0xFF), 0x00, unchecked((byte)0xFF), unchecked((byte)0xFF), 0x00, unchecked((byte)0xFF), 0x00, unchecked((byte)0xFF), 0x00, unchecked((byte)0xFF), 0x00, 0x00, unchecked((byte)0xFF), unchecked((byte)0xFF), 0x00, unchecked((byte)0xFF), 0x00, 0x00, unchecked((byte)0xFF), unchecked((byte)0xFF), 0x00, 0x00, 0x00, unchecked((byte)0xFF), unchecked((byte)0xFF), 0x00, unchecked((byte)0xFF)};

		public virtual void reset()
		{
			byteCount = 0;
			xBufOff = 0;

			for (int i = 0; i < H.Length; i++)
			{
				H[i] = 0; // start vector H
			}
			for (int i = 0; i < L.Length; i++)
			{
				L[i] = 0;
			}
			for (int i = 0; i < M.Length; i++)
			{
				M[i] = 0;
			}
			for (int i = 0; i < C[1].Length; i++)
			{
				C[1][i] = 0; // real index C = +1 because index array with 0.
			}
			for (int i = 0; i < C[3].Length; i++)
			{
				C[3][i] = 0;
			}
			for (int i = 0; i < Sum.Length; i++)
			{
				Sum[i] = 0;
			}
			for (int i = 0; i < xBuf.Length; i++)
			{
				xBuf[i] = 0;
			}

			JavaSystem.arraycopy(C2, 0, C[2], 0, C2.Length);
		}

		//  256 bitsblock modul -> (Sum + a mod (2^256))
		private void sumByteArray(byte[] @in)
		{
			int carry = 0;

			for (int i = 0; i != Sum.Length; i++)
			{
				int sum = (Sum[i] & 0xff) + (@in[i] & 0xff) + carry;

				Sum[i] = (byte)sum;

				carry = (int)((uint)sum >> 8);
			}
		}

		private void cpyBytesToShort(byte[] S, short[] wS)
		{
			for (int i = 0; i < S.Length / 2; i++)
			{
				wS[i] = unchecked((short)(((S[i * 2 + 1] << 8) & 0xFF00) | (S[i * 2] & 0xFF)));
			}
		}

		private void cpyShortToBytes(short[] wS, byte[] S)
		{
			for (int i = 0; i < S.Length / 2; i++)
			{
				S[i * 2 + 1] = (byte)(wS[i] >> 8);
				S[i * 2] = (byte)wS[i];
			}
		}

	   public virtual int getByteLength()
	   {
		  return 32;
	   }

		public virtual Memoable copy()
		{
			return new GOST3411Digest(this);
		}

		public virtual void reset(Memoable other)
		{
			GOST3411Digest t = (GOST3411Digest)other;

			this.sBox = t.sBox;
			cipher.init(true, new ParametersWithSBox(null, sBox));

			reset();

			JavaSystem.arraycopy(t.H, 0, this.H, 0, t.H.Length);
			JavaSystem.arraycopy(t.L, 0, this.L, 0, t.L.Length);
			JavaSystem.arraycopy(t.M, 0, this.M, 0, t.M.Length);
			JavaSystem.arraycopy(t.Sum, 0, this.Sum, 0, t.Sum.Length);
			JavaSystem.arraycopy(t.C[1], 0, this.C[1], 0, t.C[1].Length);
			JavaSystem.arraycopy(t.C[2], 0, this.C[2], 0, t.C[2].Length);
			JavaSystem.arraycopy(t.C[3], 0, this.C[3], 0, t.C[3].Length);
			JavaSystem.arraycopy(t.xBuf, 0, this.xBuf, 0, t.xBuf.Length);

			this.xBufOff = t.xBufOff;
			this.byteCount = t.byteCount;
		}
	}



}