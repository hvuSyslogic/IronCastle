using org.bouncycastle.crypto;
using org.bouncycastle.Port;

namespace org.bouncycastle.pqc.crypto.gmss.util
{
	
	/// <summary>
	/// This class implements signature verification of the Winternitz one-time
	/// signature scheme (OTSS), described in C.Dods, N.P. Smart, and M. Stam, "Hash
	/// Based Digital Signature Schemes", LNCS 3796, pages 96&#8211;115, 2005. The
	/// class is used by the GMSS classes.
	/// </summary>
	public class WinternitzOTSVerify
	{

		private Digest messDigestOTS;

		/// <summary>
		/// The Winternitz parameter
		/// </summary>
		private int w;

		/// <summary>
		/// The constructor
		/// </summary>
		/// <param name="digest"> the name of the hash function used by the OTS and the provider
		///               name of the hash function </param>
		/// <param name="w">      the Winternitz parameter </param>
		public WinternitzOTSVerify(Digest digest, int w)
		{
			this.w = w;

			messDigestOTS = digest;
		}

		/// <returns> The length of the one-time signature </returns>
		public virtual int getSignatureLength()
		{
			int mdsize = messDigestOTS.getDigestSize();
			int size = ((mdsize << 3) + (w - 1)) / w;
			int logs = getLog((size << w) + 1);
			size += (logs + w - 1) / w;

			return mdsize * size;
		}

		/// <summary>
		/// This method computes the public OTS key from the one-time signature of a
		/// message. This is *NOT* a complete OTS signature verification, but it
		/// suffices for usage with CMSS.
		/// </summary>
		/// <param name="message">   the message </param>
		/// <param name="signature"> the one-time signature </param>
		/// <returns> The public OTS key </returns>
		public virtual byte[] Verify(byte[] message, byte[] signature)
		{

			int mdsize = messDigestOTS.getDigestSize();
			byte[] hash = new byte[mdsize]; // hash of message m

			// create hash of message m
			messDigestOTS.update(message, 0, message.Length);
			hash = new byte[messDigestOTS.getDigestSize()];
			messDigestOTS.doFinal(hash, 0);

			int size = ((mdsize << 3) + (w - 1)) / w;
			int logs = getLog((size << w) + 1);
			int keysize = size + (logs + w - 1) / w;

			int testKeySize = mdsize * keysize;

			if (testKeySize != signature.Length)
			{
				return null;
			}

			byte[] testKey = new byte[testKeySize];

			int c = 0;
			int counter = 0;
			int test;

			if (8 % w == 0)
			{
				int d = 8 / w;
				int k = (1 << w) - 1;
				byte[] hlp = new byte[mdsize];

				// verify signature
				for (int i = 0; i < hash.Length; i++)
				{
					for (int j = 0; j < d; j++)
					{
						test = hash[i] & k;
						c += test;

						JavaSystem.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

						while (test < k)
						{
							messDigestOTS.update(hlp, 0, hlp.Length);
							hlp = new byte[messDigestOTS.getDigestSize()];
							messDigestOTS.doFinal(hlp, 0);
							test++;
						}

						JavaSystem.arraycopy(hlp, 0, testKey, counter * mdsize, mdsize);
						hash[i] = (byte)((int)((uint)hash[i] >> w));
						counter++;
					}
				}

				c = (size << w) - c;
				for (int i = 0; i < logs; i += w)
				{
					test = c & k;

					JavaSystem.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

					while (test < k)
					{
						messDigestOTS.update(hlp, 0, hlp.Length);
						hlp = new byte[messDigestOTS.getDigestSize()];
						messDigestOTS.doFinal(hlp, 0);
						test++;
					}
					JavaSystem.arraycopy(hlp, 0, testKey, counter * mdsize, mdsize);
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

						JavaSystem.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

						while (test < k)
						{
							messDigestOTS.update(hlp, 0, hlp.Length);
							hlp = new byte[messDigestOTS.getDigestSize()];
							messDigestOTS.doFinal(hlp, 0);
							test++;
						}

						JavaSystem.arraycopy(hlp, 0, testKey, counter * mdsize, mdsize);
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

					JavaSystem.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

					while (test < k)
					{
						messDigestOTS.update(hlp, 0, hlp.Length);
						hlp = new byte[messDigestOTS.getDigestSize()];
						messDigestOTS.doFinal(hlp, 0);
						test++;
					}

					JavaSystem.arraycopy(hlp, 0, testKey, counter * mdsize, mdsize);
					big8 = (long)((ulong)big8 >> w);
					counter++;
				}

				// check bytes
				c = (size << w) - c;
				for (int i = 0; i < logs; i += w)
				{
					test = c & k;

					JavaSystem.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

					while (test < k)
					{
						messDigestOTS.update(hlp, 0, hlp.Length);
						hlp = new byte[messDigestOTS.getDigestSize()];
						messDigestOTS.doFinal(hlp, 0);
						test++;
					}

					JavaSystem.arraycopy(hlp, 0, testKey, counter * mdsize, mdsize);
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

					JavaSystem.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

					while (test8 < k)
					{
						messDigestOTS.update(hlp, 0, hlp.Length);
						hlp = new byte[messDigestOTS.getDigestSize()];
						messDigestOTS.doFinal(hlp, 0);
						test8++;
					}

					JavaSystem.arraycopy(hlp, 0, testKey, counter * mdsize, mdsize);
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

					JavaSystem.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

					while (test8 < k)
					{
						messDigestOTS.update(hlp, 0, hlp.Length);
						hlp = new byte[messDigestOTS.getDigestSize()];
						messDigestOTS.doFinal(hlp, 0);
						test8++;
					}

					JavaSystem.arraycopy(hlp, 0, testKey, counter * mdsize, mdsize);
					counter++;
				}
				// check bytes
				c = (size << w) - c;
				for (int i = 0; i < logs; i += w)
				{
					test8 = (c & k);

					JavaSystem.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

					while (test8 < k)
					{
						messDigestOTS.update(hlp, 0, hlp.Length);
						hlp = new byte[messDigestOTS.getDigestSize()];
						messDigestOTS.doFinal(hlp, 0);
						test8++;
					}

					JavaSystem.arraycopy(hlp, 0, testKey, counter * mdsize, mdsize);
					c = (int)((uint)c >> w);
					counter++;
				}
			} // end if(w<57)

			byte[] TKey = new byte[mdsize];
			messDigestOTS.update(testKey, 0, testKey.Length);
			TKey = new byte[messDigestOTS.getDigestSize()];
			messDigestOTS.doFinal(TKey, 0);

			return TKey;

		}

		/// <summary>
		/// This method returns the least integer that is greater or equal to the
		/// logarithm to the base 2 of an integer <code>intValue</code>.
		/// </summary>
		/// <param name="intValue"> an integer </param>
		/// <returns> The least integer greater or equal to the logarithm to the base
		///         256 of <code>intValue</code> </returns>
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