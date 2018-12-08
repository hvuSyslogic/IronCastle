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
		private static readonly byte[] S = new byte[] {(byte)41, (byte)46, (byte)67, unchecked((byte)201), unchecked((byte)162), unchecked((byte)216), (byte)124, (byte)1, (byte)61, (byte)54, (byte)84, unchecked((byte)161), unchecked((byte)236), unchecked((byte)240), (byte)6, (byte)19, (byte)98, unchecked((byte)167), (byte)5, unchecked((byte)243), unchecked((byte)192), unchecked((byte)199), (byte)115, unchecked((byte)140), unchecked((byte)152), unchecked((byte)147), (byte)43, unchecked((byte)217), unchecked((byte)188), (byte)76, unchecked((byte)130), unchecked((byte)202), (byte)30, unchecked((byte)155), (byte)87, (byte)60, unchecked((byte)253), unchecked((byte)212), unchecked((byte)224), (byte)22, (byte)103, (byte)66, (byte)111, (byte)24, unchecked((byte)138), (byte)23, unchecked((byte)229), (byte)18, unchecked((byte)190), (byte)78, unchecked((byte)196), unchecked((byte)214), unchecked((byte)218), unchecked((byte)158), unchecked((byte)222), (byte)73, unchecked((byte)160), unchecked((byte)251), unchecked((byte)245), unchecked((byte)142), unchecked((byte)187), (byte)47, unchecked((byte)238), (byte)122, unchecked((byte)169), (byte)104, (byte)121, unchecked((byte)145), (byte)21, unchecked((byte)178), (byte)7, (byte)63, unchecked((byte)148), unchecked((byte)194), (byte)16, unchecked((byte)137), (byte)11, (byte)34, (byte)95, (byte)33, unchecked((byte)128), (byte)127, (byte)93, unchecked((byte)154), (byte)90, unchecked((byte)144), (byte)50, (byte)39, (byte)53, (byte)62, unchecked((byte)204), unchecked((byte)231), unchecked((byte)191), unchecked((byte)247), unchecked((byte)151), (byte)3, unchecked((byte)255), (byte)25, (byte)48, unchecked((byte)179), (byte)72, unchecked((byte)165), unchecked((byte)181), unchecked((byte)209), unchecked((byte)215), (byte)94, unchecked((byte)146), (byte)42, unchecked((byte)172), (byte)86, unchecked((byte)170), unchecked((byte)198), (byte)79, unchecked((byte)184), (byte)56, unchecked((byte)210), unchecked((byte)150), unchecked((byte)164), (byte)125, unchecked((byte)182), (byte)118, unchecked((byte)252), (byte)107, unchecked((byte)226), unchecked((byte)156), (byte)116, (byte)4, unchecked((byte)241), (byte)69, unchecked((byte)157), (byte)112, (byte)89, (byte)100, (byte)113, unchecked((byte)135), (byte)32, unchecked((byte)134), (byte)91, unchecked((byte)207), (byte)101, unchecked((byte)230), (byte)45, unchecked((byte)168), (byte)2, (byte)27, (byte)96, (byte)37, unchecked((byte)173), unchecked((byte)174), unchecked((byte)176), unchecked((byte)185), unchecked((byte)246), (byte)28, (byte)70, (byte)97, (byte)105, (byte)52, (byte)64, (byte)126, (byte)15, (byte)85, (byte)71, unchecked((byte)163), (byte)35, unchecked((byte)221), (byte)81, unchecked((byte)175), (byte)58, unchecked((byte)195), (byte)92, unchecked((byte)249), unchecked((byte)206), unchecked((byte)186), unchecked((byte)197), unchecked((byte)234), (byte)38, (byte)44, (byte)83, (byte)13, (byte)110, unchecked((byte)133), (byte)40, unchecked((byte)132), 9, unchecked((byte)211), unchecked((byte)223), unchecked((byte)205), unchecked((byte)244), (byte)65, unchecked((byte)129), (byte)77, (byte)82, (byte)106, unchecked((byte)220), (byte)55, unchecked((byte)200), (byte)108, unchecked((byte)193), unchecked((byte)171), unchecked((byte)250), (byte)36, unchecked((byte)225), (byte)123, (byte)8, (byte)12, unchecked((byte)189), unchecked((byte)177), (byte)74, (byte)120, unchecked((byte)136), unchecked((byte)149), unchecked((byte)139), unchecked((byte)227), (byte)99, unchecked((byte)232), (byte)109, unchecked((byte)233), unchecked((byte)203), unchecked((byte)213), unchecked((byte)254), (byte)59, (byte)0, (byte)29, (byte)57, unchecked((byte)242), unchecked((byte)239), unchecked((byte)183), (byte)14, (byte)102, (byte)88, unchecked((byte)208), unchecked((byte)228), unchecked((byte)166), (byte)119, (byte)114, unchecked((byte)248), unchecked((byte)235), (byte)117, (byte)75, (byte)10, (byte)49, (byte)68, (byte)80, unchecked((byte)180), unchecked((byte)143), unchecked((byte)237), (byte)31, (byte)26, unchecked((byte)219), unchecked((byte)153), unchecked((byte)141), (byte)51, unchecked((byte)159), (byte)17, unchecked((byte)131), (byte)20};

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