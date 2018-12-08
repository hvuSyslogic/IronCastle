using org.bouncycastle.asn1;

namespace org.bouncycastle.cert.selector
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using Pack = org.bouncycastle.util.Pack;

	public class MSOutlookKeyIdCalculator
	{
		// This is less than ideal, but it seems to be the best way of supporting this without exposing SHA-1
		// as the class is only used to workout the MSOutlook Key ID, you can think of the fact it's SHA-1 as
		// a coincidence...
		internal static byte[] calculateKeyId(SubjectPublicKeyInfo info)
		{
			SHA1Digest dig = new SHA1Digest();
			byte[] hash = new byte[dig.getDigestSize()];
			byte[] spkiEnc = new byte[0];
			try
			{
				spkiEnc = info.getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IOException)
			{
				return new byte[0];
			}

			// try the outlook 2010 calculation
			dig.update(spkiEnc, 0, spkiEnc.Length);

			dig.doFinal(hash, 0);

			return hash;
		}

		public abstract class GeneralDigest
		{
			internal const int BYTE_LENGTH = 64;
			internal byte[] xBuf;
			internal int xBufOff;

			internal long byteCount;

			/// <summary>
			/// Standard constructor
			/// </summary>
			public GeneralDigest()
			{
				xBuf = new byte[4];
				xBufOff = 0;
			}

			/// <summary>
			/// Copy constructor.  We are using copy constructors in place
			/// of the Object.clone() interface as this interface is not
			/// supported by J2ME.
			/// </summary>
			public GeneralDigest(GeneralDigest t)
			{
				xBuf = new byte[t.xBuf.Length];

				copyIn(t);
			}

			public virtual void copyIn(GeneralDigest t)
			{
				JavaSystem.arraycopy(t.xBuf, 0, xBuf, 0, t.xBuf.Length);

				xBufOff = t.xBufOff;
				byteCount = t.byteCount;
			}

			public virtual void update(byte @in)
			{
				xBuf[xBufOff++] = @in;

				if (xBufOff == xBuf.Length)
				{
					processWord(xBuf, 0);
					xBufOff = 0;
				}

				byteCount++;
			}

			public virtual void update(byte[] @in, int inOff, int len)
			{
				//
				// fill the current word
				//
				while ((xBufOff != 0) && (len > 0))
				{
					update(@in[inOff]);

					inOff++;
					len--;
				}

				//
				// process whole words.
				//
				while (len > xBuf.Length)
				{
					processWord(@in, inOff);

					inOff += xBuf.Length;
					len -= xBuf.Length;
					byteCount += xBuf.Length;
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

			public virtual void finish()
			{
				long bitLength = (byteCount << 3);

				//
				// add the pad bytes.
				//
				update(unchecked((byte)128));

				while (xBufOff != 0)
				{
					update((byte)0);
				}

				processLength(bitLength);

				processBlock();
			}

			public virtual void reset()
			{
				byteCount = 0;

				xBufOff = 0;
				for (int i = 0; i < xBuf.Length; i++)
				{
					xBuf[i] = 0;
				}
			}

			public abstract void processWord(byte[] @in, int inOff);

			public abstract void processLength(long bitLength);

			public abstract void processBlock();
		}

		public class SHA1Digest : GeneralDigest
		{
			internal const int DIGEST_LENGTH = 20;

			internal int H1, H2, H3, H4, H5;

			internal int[] X = new int[80];
			internal int xOff;

			/// <summary>
			/// Standard constructor
			/// </summary>
			public SHA1Digest()
			{
				reset();
			}

			public virtual string getAlgorithmName()
			{
				return "SHA-1";
			}

			public virtual int getDigestSize()
			{
				return DIGEST_LENGTH;
			}

			public override void processWord(byte[] @in, int inOff)
			{
				// Note: Inlined for performance
		//        X[xOff] = Pack.bigEndianToInt(in, inOff);
				int n = @in[inOff] << 24;
				n |= (@in[++inOff] & 0xff) << 16;
				n |= (@in[++inOff] & 0xff) << 8;
				n |= (@in[++inOff] & 0xff);
				X[xOff] = n;

				if (++xOff == 16)
				{
					processBlock();
				}
			}

			public override void processLength(long bitLength)
			{
				if (xOff > 14)
				{
					processBlock();
				}

				X[14] = (int)((long)((ulong)bitLength >> 32));
				X[15] = unchecked((int)(bitLength & 0xffffffff));
			}

			public virtual int doFinal(byte[] @out, int outOff)
			{
				finish();

				Pack.intToBigEndian(H1, @out, outOff);
				Pack.intToBigEndian(H2, @out, outOff + 4);
				Pack.intToBigEndian(H3, @out, outOff + 8);
				Pack.intToBigEndian(H4, @out, outOff + 12);
				Pack.intToBigEndian(H5, @out, outOff + 16);

				reset();

				return DIGEST_LENGTH;
			}

			/// <summary>
			/// reset the chaining variables
			/// </summary>
			public override void reset()
			{
				base.reset();

				H1 = 0x67452301;
				H2 = unchecked((int)0xefcdab89);
				H3 = unchecked((int)0x98badcfe);
				H4 = 0x10325476;
				H5 = unchecked((int)0xc3d2e1f0);

				xOff = 0;
				for (int i = 0; i != X.Length; i++)
				{
					X[i] = 0;
				}
			}

			//
			// Additive constants
			//
			internal const int Y1 = 0x5a827999;
			internal const int Y2 = 0x6ed9eba1;
			internal const int Y3 = unchecked((int)0x8f1bbcdc);
			internal const int Y4 = unchecked((int)0xca62c1d6);

			public virtual int f(int u, int v, int w)
			{
				return ((u & v) | ((~u) & w));
			}

			public virtual int h(int u, int v, int w)
			{
				return (u ^ v ^ w);
			}

			public virtual int g(int u, int v, int w)
			{
				return ((u & v) | (u & w) | (v & w));
			}

			public override void processBlock()
			{
				//
				// expand 16 word block into 80 word block.
				//
				for (int i = 16; i < 80; i++)
				{
					int t = X[i - 3] ^ X[i - 8] ^ X[i - 14] ^ X[i - 16];
					X[i] = t << 1 | (int)((uint)t >> 31);
				}

				//
				// set up working variables.
				//
				int A = H1;
				int B = H2;
				int C = H3;
				int D = H4;
				int E = H5;

				//
				// round 1
				//
				int idx = 0;

				for (int j = 0; j < 4; j++)
				{
					// E = rotateLeft(A, 5) + f(B, C, D) + E + X[idx++] + Y1
					// B = rotateLeft(B, 30)
					E += (A << 5 | (int)((uint)A >> 27)) + f(B, C, D) + X[idx++] + Y1;
					B = B << 30 | (int)((uint)B >> 2);

					D += (E << 5 | (int)((uint)E >> 27)) + f(A, B, C) + X[idx++] + Y1;
					A = A << 30 | (int)((uint)A >> 2);

					C += (D << 5 | (int)((uint)D >> 27)) + f(E, A, B) + X[idx++] + Y1;
					E = E << 30 | (int)((uint)E >> 2);

					B += (C << 5 | (int)((uint)C >> 27)) + f(D, E, A) + X[idx++] + Y1;
					D = D << 30 | (int)((uint)D >> 2);

					A += (B << 5 | (int)((uint)B >> 27)) + f(C, D, E) + X[idx++] + Y1;
					C = C << 30 | (int)((uint)C >> 2);
				}

				//
				// round 2
				//
				for (int j = 0; j < 4; j++)
				{
					// E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y2
					// B = rotateLeft(B, 30)
					E += (A << 5 | (int)((uint)A >> 27)) + h(B, C, D) + X[idx++] + Y2;
					B = B << 30 | (int)((uint)B >> 2);

					D += (E << 5 | (int)((uint)E >> 27)) + h(A, B, C) + X[idx++] + Y2;
					A = A << 30 | (int)((uint)A >> 2);

					C += (D << 5 | (int)((uint)D >> 27)) + h(E, A, B) + X[idx++] + Y2;
					E = E << 30 | (int)((uint)E >> 2);

					B += (C << 5 | (int)((uint)C >> 27)) + h(D, E, A) + X[idx++] + Y2;
					D = D << 30 | (int)((uint)D >> 2);

					A += (B << 5 | (int)((uint)B >> 27)) + h(C, D, E) + X[idx++] + Y2;
					C = C << 30 | (int)((uint)C >> 2);
				}

				//
				// round 3
				//
				for (int j = 0; j < 4; j++)
				{
					// E = rotateLeft(A, 5) + g(B, C, D) + E + X[idx++] + Y3
					// B = rotateLeft(B, 30)
					E += (A << 5 | (int)((uint)A >> 27)) + g(B, C, D) + X[idx++] + Y3;
					B = B << 30 | (int)((uint)B >> 2);

					D += (E << 5 | (int)((uint)E >> 27)) + g(A, B, C) + X[idx++] + Y3;
					A = A << 30 | (int)((uint)A >> 2);

					C += (D << 5 | (int)((uint)D >> 27)) + g(E, A, B) + X[idx++] + Y3;
					E = E << 30 | (int)((uint)E >> 2);

					B += (C << 5 | (int)((uint)C >> 27)) + g(D, E, A) + X[idx++] + Y3;
					D = D << 30 | (int)((uint)D >> 2);

					A += (B << 5 | (int)((uint)B >> 27)) + g(C, D, E) + X[idx++] + Y3;
					C = C << 30 | (int)((uint)C >> 2);
				}

				//
				// round 4
				//
				for (int j = 0; j <= 3; j++)
				{
					// E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y4
					// B = rotateLeft(B, 30)
					E += (A << 5 | (int)((uint)A >> 27)) + h(B, C, D) + X[idx++] + Y4;
					B = B << 30 | (int)((uint)B >> 2);

					D += (E << 5 | (int)((uint)E >> 27)) + h(A, B, C) + X[idx++] + Y4;
					A = A << 30 | (int)((uint)A >> 2);

					C += (D << 5 | (int)((uint)D >> 27)) + h(E, A, B) + X[idx++] + Y4;
					E = E << 30 | (int)((uint)E >> 2);

					B += (C << 5 | (int)((uint)C >> 27)) + h(D, E, A) + X[idx++] + Y4;
					D = D << 30 | (int)((uint)D >> 2);

					A += (B << 5 | (int)((uint)B >> 27)) + h(C, D, E) + X[idx++] + Y4;
					C = C << 30 | (int)((uint)C >> 2);
				}


				H1 += A;
				H2 += B;
				H3 += C;
				H4 += D;
				H5 += E;

				//
				// reset start of the buffer.
				//
				xOff = 0;
				for (int i = 0; i < 16; i++)
				{
					X[i] = 0;
				}
			}
		}
	}

}