using System;
using org.bouncycastle.Port;

namespace org.bouncycastle.pqc.crypto.gmss.util
{
	using Digest = org.bouncycastle.crypto.Digest;

	/// <summary>
	/// This class implements key pair generation and signature generation of the
	/// Winternitz one-time signature scheme (OTSS), described in C.Dods, N.P. Smart,
	/// and M. Stam, "Hash Based Digital Signature Schemes", LNCS 3796, pages
	/// 96&#8211;115, 2005. The class is used by the GMSS classes.
	/// </summary>

	public class WinternitzOTSignature
	{

		/// <summary>
		/// The hash function used by the OTS
		/// </summary>
		private Digest messDigestOTS;

		/// <summary>
		/// The length of the message digest and private key
		/// </summary>
		private int mdsize, keysize;

		/// <summary>
		/// An array of strings, containing the name of the used hash function, the
		/// name of the PRGN and the names of the corresponding providers
		/// </summary>
		// private String[] name = new String[2];
		/// <summary>
		/// The private key
		/// </summary>
		private byte[][] privateKeyOTS;

		/// <summary>
		/// The Winternitz parameter
		/// </summary>
		private int w;

		/// <summary>
		/// The source of randomness for OTS private key generation
		/// </summary>
		private GMSSRandom gmssRandom;

		/// <summary>
		/// Sizes of the message and the checksum, both
		/// </summary>
		private int messagesize, checksumsize;

		/// <summary>
		/// The constructor generates an OTS key pair, using <code>seed0</code> and
		/// the PRNG
		/// </summary>
		/// <param name="seed0">    the seed for the PRGN </param>
		/// <param name="digest"> an array of strings, containing the name of the used hash
		///                 function, the name of the PRGN and the names of the
		///                 corresponding providers </param>
		/// <param name="w">        the Winternitz parameter </param>
		public WinternitzOTSignature(byte[] seed0, Digest digest, int w)
		{
			// this.name = name;
			this.w = w;

			messDigestOTS = digest;

			gmssRandom = new GMSSRandom(messDigestOTS);

			// calulate keysize for private and public key and also the help
			// array

			mdsize = messDigestOTS.getDigestSize();
			int mdsizeBit = mdsize << 3;
			messagesize = (int)Math.Ceiling(mdsizeBit / (double)w);

			checksumsize = getLog((messagesize << w) + 1);

			keysize = messagesize + (int)Math.Ceiling(checksumsize / (double)w);

			/*
			   * mdsize = messDigestOTS.getDigestLength(); messagesize =
			   * ((mdsize<<3)+(w-1))/w;
			   *
			   * checksumsize = getlog((messagesize<<w)+1);
			   *
			   * keysize = messagesize + (checksumsize+w-1)/w;
			   */
			// define the private key messagesize
			privateKeyOTS = RectangularArrays.ReturnRectangularSbyteArray(keysize, mdsize);

			// gmssRandom.setSeed(seed0);
			byte[] dummy = new byte[mdsize];
			JavaSystem.arraycopy(seed0, 0, dummy, 0, dummy.Length);

			// generate random bytes and
			// assign them to the private key
			for (int i = 0; i < keysize; i++)
			{
				privateKeyOTS[i] = gmssRandom.nextSeed(dummy);
			}
		}

		/// <returns> The private OTS key </returns>
		public virtual byte[][] getPrivateKey()
		{
			return privateKeyOTS;
		}

		/// <returns> The public OTS key </returns>
		public virtual byte[] getPublicKey()
		{
			byte[] helppubKey = new byte[keysize * mdsize];

			byte[] help = new byte[mdsize];
			int two_power_t = 1 << w;

			for (int i = 0; i < keysize; i++)
			{
				// hash w-1 time the private key and assign it to the public key
				messDigestOTS.update(privateKeyOTS[i], 0, privateKeyOTS[i].Length);
				help = new byte[messDigestOTS.getDigestSize()];
				messDigestOTS.doFinal(help, 0);
				for (int j = 2; j < two_power_t; j++)
				{
					messDigestOTS.update(help, 0, help.Length);
					help = new byte[messDigestOTS.getDigestSize()];
					messDigestOTS.doFinal(help, 0);
				}
				JavaSystem.arraycopy(help, 0, helppubKey, mdsize * i, mdsize);
			}

			messDigestOTS.update(helppubKey, 0, helppubKey.Length);
			byte[] tmp = new byte[messDigestOTS.getDigestSize()];
			messDigestOTS.doFinal(tmp, 0);
			return tmp;
		}

		/// <returns> The one-time signature of the message, generated with the private
		///         key </returns>
		public virtual byte[] getSignature(byte[] message)
		{
			byte[] sign = new byte[keysize * mdsize];
			// byte [] message; // message m as input
			byte[] hash = new byte[mdsize]; // hash of message m
			int counter = 0;
			int c = 0;
			int test = 0;
			// create hash of message m
			messDigestOTS.update(message, 0, message.Length);
			hash = new byte[messDigestOTS.getDigestSize()];
			messDigestOTS.doFinal(hash, 0);

			if (8 % w == 0)
			{
				int d = 8 / w;
				int k = (1 << w) - 1;
				byte[] hlp = new byte[mdsize];

				// create signature
				for (int i = 0; i < hash.Length; i++)
				{
					for (int j = 0; j < d; j++)
					{
						test = hash[i] & k;
						c += test;

						JavaSystem.arraycopy(privateKeyOTS[counter], 0, hlp, 0, mdsize);

						while (test > 0)
						{
							messDigestOTS.update(hlp, 0, hlp.Length);
							hlp = new byte[messDigestOTS.getDigestSize()];
							messDigestOTS.doFinal(hlp, 0);
							test--;
						}
						JavaSystem.arraycopy(hlp, 0, sign, counter * mdsize, mdsize);
						hash[i] = (byte)((int)((uint)hash[i] >> w));
						counter++;
					}
				}

				c = (messagesize << w) - c;
				for (int i = 0; i < checksumsize; i += w)
				{
					test = c & k;

					JavaSystem.arraycopy(privateKeyOTS[counter], 0, hlp, 0, mdsize);

					while (test > 0)
					{
						messDigestOTS.update(hlp, 0, hlp.Length);
						hlp = new byte[messDigestOTS.getDigestSize()];
						messDigestOTS.doFinal(hlp, 0);
						test--;
					}
					JavaSystem.arraycopy(hlp, 0, sign, counter * mdsize, mdsize);
					c = (int)((uint)c >> w);
					counter++;
				}
			}
			else if (w < 8)
			{
				int d = mdsize / w;
				int k = (1 << w) - 1;
				byte[] hlp = new byte[mdsize];
				long big8;
				int ii = 0;
				// create signature
				// first d*w bytes of hash
				for (int i = 0; i < d; i++)
				{
					big8 = 0;
					for (int j = 0; j < w; j++)
					{
						big8 ^= (hash[ii] & 0xff) << (j << 3);
						ii++;
					}
					for (int j = 0; j < 8; j++)
					{
						test = (int)(big8 & k);
						c += test;

						JavaSystem.arraycopy(privateKeyOTS[counter], 0, hlp, 0, mdsize);

						while (test > 0)
						{
							messDigestOTS.update(hlp, 0, hlp.Length);
							hlp = new byte[messDigestOTS.getDigestSize()];
							messDigestOTS.doFinal(hlp, 0);
							test--;
						}
						JavaSystem.arraycopy(hlp, 0, sign, counter * mdsize, mdsize);
						big8 = (long)((ulong)big8 >> w);
						counter++;
					}
				}
				// rest of hash
				d = mdsize % w;
				big8 = 0;
				for (int j = 0; j < d; j++)
				{
					big8 ^= (hash[ii] & 0xff) << (j << 3);
					ii++;
				}
				d <<= 3;
				for (int j = 0; j < d; j += w)
				{
					test = (int)(big8 & k);
					c += test;

					JavaSystem.arraycopy(privateKeyOTS[counter], 0, hlp, 0, mdsize);

					while (test > 0)
					{
						messDigestOTS.update(hlp, 0, hlp.Length);
						hlp = new byte[messDigestOTS.getDigestSize()];
						messDigestOTS.doFinal(hlp, 0);
						test--;
					}
					JavaSystem.arraycopy(hlp, 0, sign, counter * mdsize, mdsize);
					big8 = (long)((ulong)big8 >> w);
					counter++;
				}

				// check bytes
				c = (messagesize << w) - c;
				for (int i = 0; i < checksumsize; i += w)
				{
					test = c & k;

					JavaSystem.arraycopy(privateKeyOTS[counter], 0, hlp, 0, mdsize);

					while (test > 0)
					{
						messDigestOTS.update(hlp, 0, hlp.Length);
						hlp = new byte[messDigestOTS.getDigestSize()];
						messDigestOTS.doFinal(hlp, 0);
						test--;
					}
					JavaSystem.arraycopy(hlp, 0, sign, counter * mdsize, mdsize);
					c = (int)((uint)c >> w);
					counter++;
				}
			} // end if(w<8)
			else if (w < 57)
			{
				int d = (mdsize << 3) - w;
				int k = (1 << w) - 1;
				byte[] hlp = new byte[mdsize];
				long big8, test8;
				int r = 0;
				int s, f, rest, ii;
				// create signature
				// first a*w bits of hash where a*w <= 8*mdsize < (a+1)*w
				while (r <= d)
				{
					s = (int)((uint)r >> 3);
					rest = r % 8;
					r += w;
					f = (int)((uint)(r + 7) >> 3);
					big8 = 0;
					ii = 0;
					for (int j = s; j < f; j++)
					{
						big8 ^= (hash[j] & 0xff) << (ii << 3);
						ii++;
					}

					big8 = (long)((ulong)big8 >> rest);
					test8 = (big8 & k);
					c += (int)test8;

					JavaSystem.arraycopy(privateKeyOTS[counter], 0, hlp, 0, mdsize);
					while (test8 > 0)
					{
						messDigestOTS.update(hlp, 0, hlp.Length);
						hlp = new byte[messDigestOTS.getDigestSize()];
						messDigestOTS.doFinal(hlp, 0);
						test8--;
					}
					JavaSystem.arraycopy(hlp, 0, sign, counter * mdsize, mdsize);
					counter++;

				}
				// rest of hash
				s = (int)((uint)r >> 3);
				if (s < mdsize)
				{
					rest = r % 8;
					big8 = 0;
					ii = 0;
					for (int j = s; j < mdsize; j++)
					{
						big8 ^= (hash[j] & 0xff) << (ii << 3);
						ii++;
					}

					big8 = (long)((ulong)big8 >> rest);
					test8 = (big8 & k);
					c += (int)test8;

					JavaSystem.arraycopy(privateKeyOTS[counter], 0, hlp, 0, mdsize);
					while (test8 > 0)
					{
						messDigestOTS.update(hlp, 0, hlp.Length);
						hlp = new byte[messDigestOTS.getDigestSize()];
						messDigestOTS.doFinal(hlp, 0);
						test8--;
					}
					JavaSystem.arraycopy(hlp, 0, sign, counter * mdsize, mdsize);
					counter++;
				}
				// check bytes
				c = (messagesize << w) - c;
				for (int i = 0; i < checksumsize; i += w)
				{
					test8 = (c & k);

					JavaSystem.arraycopy(privateKeyOTS[counter], 0, hlp, 0, mdsize);

					while (test8 > 0)
					{
						messDigestOTS.update(hlp, 0, hlp.Length);
						hlp = new byte[messDigestOTS.getDigestSize()];
						messDigestOTS.doFinal(hlp, 0);
						test8--;
					}
					JavaSystem.arraycopy(hlp, 0, sign, counter * mdsize, mdsize);
					c = (int)((uint)c >> w);
					counter++;
				}
			} // end if(w<57)

			return sign;
		}

		/// <summary>
		/// This method returns the least integer that is greater or equal to the
		/// logarithm to the base 2 of an integer <code>intValue</code>.
		/// </summary>
		/// <param name="intValue"> an integer </param>
		/// <returns> The least integer greater or equal to the logarithm to the base 2
		///         of <code>intValue</code> </returns>
		public virtual int getLog(int intValue)
		{
			int log = 1;
			int i = 2;
			while (i < intValue)
			{
				i <<= 1;
				log++;
			}
			return log;
		}

	}

}