using System;
using org.bouncycastle.crypto;
using org.bouncycastle.pqc.crypto.gmss.util;
using org.bouncycastle.Port;
using org.bouncycastle.util;
using org.bouncycastle.util.encoders;

namespace org.bouncycastle.pqc.crypto.gmss
{
				

	/// <summary>
	/// This class implements the distributed computation of the public key of the
	/// Winternitz one-time signature scheme (OTSS). The class is used by the GMSS
	/// classes for calculation of upcoming leafs.
	/// </summary>
	public class GMSSLeaf
	{

		/// <summary>
		/// The hash function used by the OTS and the PRNG
		/// </summary>
		private Digest messDigestOTS;

		/// <summary>
		/// The length of the message digest and private key
		/// </summary>
		private int mdsize, keysize;

		/// <summary>
		/// The source of randomness for OTS private key generation
		/// </summary>
		private GMSSRandom gmssRandom;

		/// <summary>
		/// Byte array for distributed computation of the upcoming leaf
		/// </summary>
		private byte[] leaf;

		/// <summary>
		/// Byte array for storing the concatenated hashes of private key parts
		/// </summary>
		private byte[] concHashs;

		/// <summary>
		/// indices for distributed computation
		/// </summary>
		private int i, j;

		/// <summary>
		/// storing 2^w
		/// </summary>
		private int two_power_w;

		/// <summary>
		/// Winternitz parameter w
		/// </summary>
		private int w;

		/// <summary>
		/// the amount of distributed computation steps when updateLeaf is called
		/// </summary>
		private int steps;

		/// <summary>
		/// the internal seed
		/// </summary>
		private byte[] seed;

		/// <summary>
		/// the OTS privateKey parts
		/// </summary>
		internal byte[] privateKeyOTS;

		/// <summary>
		/// This constructor regenerates a prior GMSSLeaf object
		/// </summary>
		/// <param name="digest">   an array of strings, containing the name of the used hash
		///                 function and PRNG and the name of the corresponding
		///                 provider </param>
		/// <param name="otsIndex"> status bytes </param>
		/// <param name="numLeafs"> status ints </param>
		public GMSSLeaf(Digest digest, byte[][] otsIndex, int[] numLeafs)
		{
			this.i = numLeafs[0];
			this.j = numLeafs[1];
			this.steps = numLeafs[2];
			this.w = numLeafs[3];

			messDigestOTS = digest;

			gmssRandom = new GMSSRandom(messDigestOTS);

			// calulate keysize for private key and the help array
			mdsize = messDigestOTS.getDigestSize();
			int mdsizeBit = mdsize << 3;
			int messagesize = (int)Math.Ceiling(mdsizeBit / (double)w);
			int checksumsize = getLog((messagesize << w) + 1);
			this.keysize = messagesize + (int)Math.Ceiling(checksumsize / (double)w);
			this.two_power_w = 1 << w;

			// calculate steps
			// ((2^w)-1)*keysize + keysize + 1 / (2^h -1)

			// initialize arrays
			this.privateKeyOTS = otsIndex[0];
			this.seed = otsIndex[1];
			this.concHashs = otsIndex[2];
			this.leaf = otsIndex[3];
		}

		/// <summary>
		/// The constructor precomputes some needed variables for distributed leaf
		/// calculation
		/// </summary>
		/// <param name="digest">   an array of strings, containing the digest of the used hash
		///                 function and PRNG and the digest of the corresponding
		///                 provider </param>
		/// <param name="w">        the winterniz parameter of that tree the leaf is computed
		///                 for </param>
		/// <param name="numLeafs"> the number of leafs of the tree from where the distributed
		///                 computation is called </param>
		public GMSSLeaf(Digest digest, int w, int numLeafs)
		{
			this.w = w;

			messDigestOTS = digest;

			gmssRandom = new GMSSRandom(messDigestOTS);

			// calulate keysize for private key and the help array
			mdsize = messDigestOTS.getDigestSize();
			int mdsizeBit = mdsize << 3;
			int messagesize = (int)Math.Ceiling(mdsizeBit / (double)w);
			int checksumsize = getLog((messagesize << w) + 1);
			this.keysize = messagesize + (int)Math.Ceiling(checksumsize / (double)w);
			this.two_power_w = 1 << w;

			// calculate steps
			// ((2^w)-1)*keysize + keysize + 1 / (2^h -1)
			this.steps = (int)Math.Ceiling((((1 << w) - 1) * keysize + 1 + keysize) / (double)(numLeafs));

			// initialize arrays
			this.seed = new byte[mdsize];
			this.leaf = new byte[mdsize];
			this.privateKeyOTS = new byte[mdsize];
			this.concHashs = new byte[mdsize * keysize];
		}

		public GMSSLeaf(Digest digest, int w, int numLeafs, byte[] seed0)
		{
			this.w = w;

			messDigestOTS = digest;

			gmssRandom = new GMSSRandom(messDigestOTS);

			// calulate keysize for private key and the help array
			mdsize = messDigestOTS.getDigestSize();
			int mdsizeBit = mdsize << 3;
			int messagesize = (int)Math.Ceiling(mdsizeBit / (double)w);
			int checksumsize = getLog((messagesize << w) + 1);
			this.keysize = messagesize + (int)Math.Ceiling(checksumsize / (double)w);
			this.two_power_w = 1 << w;

			// calculate steps
			// ((2^w)-1)*keysize + keysize + 1 / (2^h -1)
			this.steps = (int)Math.Ceiling((((1 << w) - 1) * keysize + 1 + keysize) / (double)(numLeafs));

			// initialize arrays
			this.seed = new byte[mdsize];
			this.leaf = new byte[mdsize];
			this.privateKeyOTS = new byte[mdsize];
			this.concHashs = new byte[mdsize * keysize];

			initLeafCalc(seed0);
		}

		private GMSSLeaf(GMSSLeaf original)
		{
			this.messDigestOTS = original.messDigestOTS;
			this.mdsize = original.mdsize;
			this.keysize = original.keysize;
			this.gmssRandom = original.gmssRandom;
			this.leaf = Arrays.clone(original.leaf);
			this.concHashs = Arrays.clone(original.concHashs);
			this.i = original.i;
			this.j = original.j;
			this.two_power_w = original.two_power_w;
			this.w = original.w;
			this.steps = original.steps;
			this.seed = Arrays.clone(original.seed);
			this.privateKeyOTS = Arrays.clone(original.privateKeyOTS);
		}

		/// <summary>
		/// initialize the distributed leaf calculation reset i,j and compute OTSseed
		/// with seed0
		/// </summary>
		/// <param name="seed0"> the starting seed </param>
		// TODO: this really looks like it should be either always called from a constructor or nextLeaf.
		public virtual void initLeafCalc(byte[] seed0)
		{
			this.i = 0;
			this.j = 0;
			byte[] dummy = new byte[mdsize];
			JavaSystem.arraycopy(seed0, 0, dummy, 0, seed.Length);
			this.seed = gmssRandom.nextSeed(dummy);
		}

		public virtual GMSSLeaf nextLeaf()
		{
			GMSSLeaf nextLeaf = new GMSSLeaf(this);

			nextLeaf.updateLeafCalc();

			return nextLeaf;
		}

		/// <summary>
		/// Processes <code>steps</code> steps of distributed leaf calculation
		/// </summary>
		/// <returns> true if leaf is completed, else false </returns>
		private void updateLeafCalc()
		{
			byte[] buf = new byte[messDigestOTS.getDigestSize()];

			// steps times do
			// TODO: this really needs to be looked at, the 10000 has been added as
			// prior to this the leaf value always ended up as zeros.
			for (int s = 0; s < steps + 10000; s++)
			{
				if (i == keysize && j == two_power_w - 1)
				{ // [3] at last hash the
					// concatenation
					messDigestOTS.update(concHashs, 0, concHashs.Length);
					leaf = new byte[messDigestOTS.getDigestSize()];
					messDigestOTS.doFinal(leaf, 0);
					return;
				}
				else if (i == 0 || j == two_power_w - 1)
				{ // [1] at the
					// beginning and
					// when [2] is
					// finished: get the
					// next private key
					// part
					i++;
					j = 0;
					// get next privKey part
					this.privateKeyOTS = gmssRandom.nextSeed(seed);
				}
				else
				{ // [2] hash the privKey part
					messDigestOTS.update(privateKeyOTS, 0, privateKeyOTS.Length);
					privateKeyOTS = buf;
					messDigestOTS.doFinal(privateKeyOTS, 0);
					j++;
					if (j == two_power_w - 1)
					{ // after w hashes add to the
						// concatenated array
						JavaSystem.arraycopy(privateKeyOTS, 0, concHashs, mdsize * (i - 1), mdsize);
					}
				}
			}

			throw new IllegalStateException("unable to updateLeaf in steps: " + steps + " " + i + " " + j);
		}

		/// <summary>
		/// Returns the leaf value.
		/// </summary>
		/// <returns> the leaf value </returns>
		public virtual byte[] getLeaf()
		{
			return Arrays.clone(leaf);
		}

		/// <summary>
		/// This method returns the least integer that is greater or equal to the
		/// logarithm to the base 2 of an integer <code>intValue</code>.
		/// </summary>
		/// <param name="intValue"> an integer </param>
		/// <returns> The least integer greater or equal to the logarithm to the base 2
		/// of <code>intValue</code> </returns>
		private int getLog(int intValue)
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

		/// <summary>
		/// Returns the status byte array used by the GMSSPrivateKeyASN.1 class
		/// </summary>
		/// <returns> The status bytes </returns>
		public virtual byte[][] getStatByte()
		{

			byte[][] statByte = new byte[4][];
			statByte[0] = privateKeyOTS;
			statByte[1] = seed;
			statByte[2] = concHashs;
			statByte[3] = leaf;

			return statByte;
		}

		/// <summary>
		/// Returns the status int array used by the GMSSPrivateKeyASN.1 class
		/// </summary>
		/// <returns> The status ints </returns>
		public virtual int[] getStatInt()
		{

			int[] statInt = new int[4];
			statInt[0] = i;
			statInt[1] = j;
			statInt[2] = steps;
			statInt[3] = w;
			return statInt;
		}

		/// <summary>
		/// Returns a String representation of the main part of this element
		/// </summary>
		/// <returns> a String representation of the main part of this element </returns>
		public override string ToString()
		{
			string @out = "";

			for (int i = 0; i < 4; i++)
			{
				@out = @out + this.getStatInt()[i] + " ";
			}
			@out = @out + " " + this.mdsize + " " + this.keysize + " "
				+ this.two_power_w + " ";

			byte[][] temp = this.getStatByte();
			for (int i = 0; i < 4; i++)
			{
				if (temp[i] != null)
				{
					@out = @out + StringHelper.NewString(Hex.encode(temp[i])) + " ";
				}
				else
				{
					@out = @out + "null ";
				}
			}
			return @out;
		}
	}

}