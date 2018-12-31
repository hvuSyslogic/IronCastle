using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.digests
{
	using org.bouncycastle.crypto;
	using Memoable = org.bouncycastle.util.Memoable;

	/// <summary>
	/// implementation of MD2
	/// as outlined in RFC1319 by B.Kaliski from RSA Laboratories April 1992
	/// </summary>
	public class MD2Digest : ExtendedDigest, Memoable
	{
		private const int DIGEST_LENGTH = 16;

		/* X buffer */
		private byte[] X = new byte[48];
		private int xOff;
		/* M buffer */
		private byte[] M = new byte[16];
		private int mOff;
		/* check sum */
		private byte[] C = new byte[16];
		private int COff;

		public MD2Digest()
		{
			reset();
		}

		public MD2Digest(MD2Digest t)
		{
			copyIn(t);
		}

		private void copyIn(MD2Digest t)
		{
			JavaSystem.arraycopy(t.X, 0, X, 0, t.X.Length);
			xOff = t.xOff;
			JavaSystem.arraycopy(t.M, 0, M, 0, t.M.Length);
			mOff = t.mOff;
			JavaSystem.arraycopy(t.C, 0, C, 0, t.C.Length);
			COff = t.COff;
		}

		/// <summary>
		/// return the algorithm name
		/// </summary>
		/// <returns> the algorithm name </returns>
		public virtual string getAlgorithmName()
		{
			return "MD2";
		}
		/// <summary>
		/// return the size, in bytes, of the digest produced by this message digest.
		/// </summary>
		/// <returns> the size, in bytes, of the digest produced by this message digest. </returns>
		public virtual int getDigestSize()
		{
			return DIGEST_LENGTH;
		}
		/// <summary>
		/// close the digest, producing the final digest value. The doFinal
		/// call leaves the digest reset.
		/// </summary>
		/// <param name="out"> the array the digest is to be copied into. </param>
		/// <param name="outOff"> the offset into the out array the digest is to start at. </param>
		public virtual int doFinal(byte[] @out, int outOff)
		{
			// add padding
			byte paddingByte = (byte)(M.Length - mOff);
			for (int i = mOff;i < M.Length;i++)
			{
				M[i] = paddingByte;
			}
			//do final check sum
			processCheckSum(M);
			// do final block process
			processBlock(M);

			processBlock(C);

			JavaSystem.arraycopy(X,xOff,@out,outOff,16);

			reset();

			return DIGEST_LENGTH;
		}
		/// <summary>
		/// reset the digest back to it's initial state.
		/// </summary>
		public virtual void reset()
		{
			xOff = 0;
			for (int i = 0; i != X.Length; i++)
			{
				X[i] = 0;
			}
			mOff = 0;
			for (int i = 0; i != M.Length; i++)
			{
				M[i] = 0;
			}
			COff = 0;
			for (int i = 0; i != C.Length; i++)
			{
				C[i] = 0;
			}
		}
		/// <summary>
		/// update the message digest with a single byte.
		/// </summary>
		/// <param name="in"> the input byte to be entered. </param>
		public virtual void update(byte @in)
		{
			M[mOff++] = @in;

			if (mOff == 16)
			{
				processCheckSum(M);
				processBlock(M);
				mOff = 0;
			}
		}

		/// <summary>
		/// update the message digest with a block of bytes.
		/// </summary>
		/// <param name="in"> the byte array containing the data. </param>
		/// <param name="inOff"> the offset into the byte array where the data starts. </param>
		/// <param name="len"> the length of the data. </param>
		public virtual void update(byte[] @in, int inOff, int len)
		{
			//
			// fill the current word
			//
			while ((mOff != 0) && (len > 0))
			{
				update(@in[inOff]);
				inOff++;
				len--;
			}

			//
			// process whole words.
			//
			while (len > 16)
			{
				JavaSystem.arraycopy(@in,inOff,M,0,16);
				processCheckSum(M);
				processBlock(M);
				len -= 16;
				inOff += 16;
			}

			//
			// load in the remainder.
			//
			while (len > 0)
			{
				update(@in[inOff]);
				inOff++;
				len--;
			}
		}
		public virtual void processCheckSum(byte[] m)
		{
			int L = C[15];
			for (int i = 0;i < 16;i++)
			{
				C[i] ^= S[(m[i] ^ L) & 0xff];
				L = C[i];
			}
		}
		public virtual void processBlock(byte[] m)
		{
			for (int i = 0;i < 16;i++)
			{
				X[i + 16] = m[i];
				X[i + 32] = (byte)(m[i] ^ X[i]);
			}
			// encrypt block
			int t = 0;

			for (int j = 0;j < 18;j++)
			{
				for (int k = 0;k < 48;k++)
				{
					t = X[k] ^= S[t];
					t = t & 0xff;
				}
				t = (t + j) % 256;
			}
		}
		 // 256-byte random permutation constructed from the digits of PI
		private static readonly byte[] S = new byte[] {41, 46, 67, unchecked(201), unchecked(162), unchecked(216), 124, 1, 61, 54, 84, unchecked(161), unchecked(236), unchecked(240), 6, 19, 98, unchecked(167), 5, unchecked(243), unchecked(192), unchecked(199), 115, unchecked(140), unchecked(152), unchecked(147), 43, unchecked(217), unchecked(188), 76, unchecked(130), unchecked(202), 30, unchecked(155), 87, 60, unchecked(253), unchecked(212), unchecked(224), 22, 103, 66, 111, 24, unchecked(138), 23, unchecked(229), 18, unchecked(190), 78, unchecked(196), unchecked(214), unchecked(218), unchecked(158), unchecked(222), 73, unchecked(160), unchecked(251), unchecked(245), unchecked(142), unchecked(187), 47, unchecked(238), 122, unchecked(169), 104, 121, unchecked(145), 21, unchecked(178), 7, 63, unchecked(148), unchecked(194), 16, unchecked(137), 11, 34, 95, 33, unchecked(128), 127, 93, unchecked(154), 90, unchecked(144), 50, 39, 53, 62, unchecked(204), unchecked(231), unchecked(191), unchecked(247), unchecked(151), 3, unchecked(255), 25, 48, unchecked(179), 72, unchecked(165), unchecked(181), unchecked(209), unchecked(215), 94, unchecked(146), 42, unchecked(172), 86, unchecked(170), unchecked(198), 79, unchecked(184), 56, unchecked(210), unchecked(150), unchecked(164), 125, unchecked(182), 118, unchecked(252), 107, unchecked(226), unchecked(156), 116, 4, unchecked(241), 69, unchecked(157), 112, 89, 100, 113, unchecked(135), 32, unchecked(134), 91, unchecked(207), 101, unchecked(230), 45, unchecked(168), 2, 27, 96, 37, unchecked(173), unchecked(174), unchecked(176), unchecked(185), unchecked(246), 28, 70, 97, 105, 52, 64, 126, 15, 85, 71, unchecked(163), 35, unchecked(221), 81, unchecked(175), 58, unchecked(195), 92, unchecked(249), unchecked(206), unchecked(186), unchecked(197), unchecked(234), 38, 44, 83, 13, 110, unchecked(133), 40, unchecked(132), 9, unchecked(211), unchecked(223), unchecked(205), unchecked(244), 65, unchecked(129), 77, 82, 106, unchecked(220), 55, unchecked(200), 108, unchecked(193), unchecked(171), unchecked(250), 36, unchecked(225), 123, 8, 12, unchecked(189), unchecked(177), 74, 120, unchecked(136), unchecked(149), unchecked(139), unchecked(227), 99, unchecked(232), 109, unchecked(233), unchecked(203), unchecked(213), unchecked(254), 59, 0, 29, 57, unchecked(242), unchecked(239), unchecked(183), 14, 102, 88, unchecked(208), unchecked(228), unchecked(166), 119, 114, unchecked(248), unchecked(235), 117, 75, 10, 49, 68, 80, unchecked(180), unchecked(143), unchecked(237), 31, 26, unchecked(219), unchecked(153), unchecked(141), 51, unchecked(159), 17, unchecked(131), 20};

	   public virtual int getByteLength()
	   {
		  return 16;
	   }

		public virtual Memoable copy()
		{
			return new MD2Digest(this);
		}

		public virtual void reset(Memoable other)
		{
			MD2Digest d = (MD2Digest)other;

			copyIn(d);
		}
	}



}