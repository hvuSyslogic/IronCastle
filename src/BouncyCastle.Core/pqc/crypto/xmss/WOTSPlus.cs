using System;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;

namespace org.bouncycastle.pqc.crypto.xmss
{

	
	/// <summary>
	/// WOTS+.
	/// </summary>
	public sealed class WOTSPlus
	{

		/// <summary>
		/// WOTS+ parameters.
		/// </summary>
		private readonly WOTSPlusParameters @params;
		/// <summary>
		/// Randomization functions.
		/// </summary>
		private readonly KeyedHashFunctions khf;
		/// <summary>
		/// WOTS+ secret key seed.
		/// </summary>
		private byte[] secretKeySeed;
		/// <summary>
		/// WOTS+ public seed.
		/// </summary>
		private byte[] publicSeed;

		/// <summary>
		/// Constructs a new WOTS+ one-time signature system based on the given WOTS+
		/// parameters.
		/// </summary>
		/// <param name="params"> Parameters for WOTSPlus object. </param>
		public WOTSPlus(WOTSPlusParameters @params) : base()
		{
			if (@params == null)
			{
				throw new NullPointerException("params == null");
			}
			this.@params = @params;
			int n = @params.getDigestSize();
			khf = new KeyedHashFunctions(@params.getDigest(), n);
			secretKeySeed = new byte[n];
			publicSeed = new byte[n];
		}

		/// <summary>
		/// Import keys to WOTS+ instance.
		/// </summary>
		/// <param name="secretKeySeed"> Secret key seed. </param>
		/// <param name="publicSeed">    Public seed. </param>
		public void importKeys(byte[] secretKeySeed, byte[] publicSeed)
		{
			if (secretKeySeed == null)
			{
				throw new NullPointerException("secretKeySeed == null");
			}
			if (secretKeySeed.Length != @params.getDigestSize())
			{
				throw new IllegalArgumentException("size of secretKeySeed needs to be equal to size of digest");
			}
			if (publicSeed == null)
			{
				throw new NullPointerException("publicSeed == null");
			}
			if (publicSeed.Length != @params.getDigestSize())
			{
				throw new IllegalArgumentException("size of publicSeed needs to be equal to size of digest");
			}
			this.secretKeySeed = secretKeySeed;
			this.publicSeed = publicSeed;
		}

		/// <summary>
		/// Creates a signature for the n-byte messageDigest.
		/// </summary>
		/// <param name="messageDigest">  Digest to sign. </param>
		/// <param name="otsHashAddress"> OTS hash address for randomization. </param>
		/// <returns> WOTS+ signature. </returns>
		public WOTSPlusSignature sign(byte[] messageDigest, OTSHashAddress otsHashAddress)
		{
			if (messageDigest == null)
			{
				throw new NullPointerException("messageDigest == null");
			}
			if (messageDigest.Length != @params.getDigestSize())
			{
				throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
			}
			if (otsHashAddress == null)
			{
				throw new NullPointerException("otsHashAddress == null");
			}
			List<int> baseWMessage = convertToBaseW(messageDigest, @params.getWinternitzParameter(), @params.getLen1());
			/* create checksum */
			int checksum = 0;
			for (int i = 0; i < @params.getLen1(); i++)
			{
				checksum += @params.getWinternitzParameter() - 1 - baseWMessage.get(i);
			}
			checksum <<= (8 - ((@params.getLen2() * XMSSUtil.log2(@params.getWinternitzParameter())) % 8));
			int len2Bytes = (int)Math.Ceiling((double)(@params.getLen2() * XMSSUtil.log2(@params.getWinternitzParameter())) / 8);
			List<int> baseWChecksum = convertToBaseW(XMSSUtil.toBytesBigEndian(checksum, len2Bytes), @params.getWinternitzParameter(), @params.getLen2());

			/* msg || checksum */
			baseWMessage.addAll(baseWChecksum);

			/* create signature */
			byte[][] signature = new byte[@params.getLen()][];
			for (int i = 0; i < @params.getLen(); i++)
			{
				otsHashAddress = (OTSHashAddress)(new OTSHashAddress.Builder()).withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress()).withOTSAddress(otsHashAddress.getOTSAddress()).withChainAddress(i).withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask()).build();
				signature[i] = chain(expandSecretKeySeed(i), 0, baseWMessage.get(i), otsHashAddress);
			}
			return new WOTSPlusSignature(@params, signature);
		}

		/// <summary>
		/// Verifies signature on message.
		/// </summary>
		/// <param name="messageDigest">  The digest that was signed. </param>
		/// <param name="signature">      Signature on digest. </param>
		/// <param name="otsHashAddress"> OTS hash address for randomization. </param>
		/// <returns> true if signature was correct false else. </returns>
		public bool verifySignature(byte[] messageDigest, WOTSPlusSignature signature, OTSHashAddress otsHashAddress)
		{
			if (messageDigest == null)
			{
				throw new NullPointerException("messageDigest == null");
			}
			if (messageDigest.Length != @params.getDigestSize())
			{
				throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
			}
			if (signature == null)
			{
				throw new NullPointerException("signature == null");
			}
			if (otsHashAddress == null)
			{
				throw new NullPointerException("otsHashAddress == null");
			}
			byte[][] tmpPublicKey = getPublicKeyFromSignature(messageDigest, signature, otsHashAddress).toByteArray();
			/* compare values */
			return XMSSUtil.areEqual(tmpPublicKey, getPublicKey(otsHashAddress).toByteArray()) ? true : false;
		}

		/// <summary>
		/// Calculates a public key based on digest and signature.
		/// </summary>
		/// <param name="messageDigest">  The digest that was signed. </param>
		/// <param name="signature">      Signarure on digest. </param>
		/// <param name="otsHashAddress"> OTS hash address for randomization. </param>
		/// <returns> WOTS+ public key derived from digest and signature. </returns>
		public WOTSPlusPublicKeyParameters getPublicKeyFromSignature(byte[] messageDigest, WOTSPlusSignature signature, OTSHashAddress otsHashAddress)
		{
			if (messageDigest == null)
			{
				throw new NullPointerException("messageDigest == null");
			}
			if (messageDigest.Length != @params.getDigestSize())
			{
				throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
			}
			if (signature == null)
			{
				throw new NullPointerException("signature == null");
			}
			if (otsHashAddress == null)
			{
				throw new NullPointerException("otsHashAddress == null");
			}
			List<int> baseWMessage = convertToBaseW(messageDigest, @params.getWinternitzParameter(), @params.getLen1());
			/* create checksum */
			int checksum = 0;
			for (int i = 0; i < @params.getLen1(); i++)
			{
				checksum += @params.getWinternitzParameter() - 1 - baseWMessage.get(i);
			}
			checksum <<= (8 - ((@params.getLen2() * XMSSUtil.log2(@params.getWinternitzParameter())) % 8));
			int len2Bytes = (int)Math.Ceiling((double)(@params.getLen2() * XMSSUtil.log2(@params.getWinternitzParameter())) / 8);
			List<int> baseWChecksum = convertToBaseW(XMSSUtil.toBytesBigEndian(checksum, len2Bytes), @params.getWinternitzParameter(), @params.getLen2());

			/* msg || checksum */
			baseWMessage.addAll(baseWChecksum);

			byte[][] publicKey = new byte[@params.getLen()][];
			for (int i = 0; i < @params.getLen(); i++)
			{
				otsHashAddress = (OTSHashAddress)(new OTSHashAddress.Builder()).withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress()).withOTSAddress(otsHashAddress.getOTSAddress()).withChainAddress(i).withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask()).build();
				publicKey[i] = chain(signature.toByteArray()[i], baseWMessage.get(i), @params.getWinternitzParameter() - 1 - baseWMessage.get(i), otsHashAddress);
			}
			return new WOTSPlusPublicKeyParameters(@params, publicKey);
		}

		/// <summary>
		/// Computes an iteration of F on an n-byte input using outputs of PRF.
		/// </summary>
		/// <param name="startHash">      Starting point. </param>
		/// <param name="startIndex">     Start index. </param>
		/// <param name="steps">          Steps to take. </param>
		/// <param name="otsHashAddress"> OTS hash address for randomization. </param>
		/// <returns> Value obtained by iterating F for steps times on input startHash,
		/// using the outputs of PRF. </returns>
		private byte[] chain(byte[] startHash, int startIndex, int steps, OTSHashAddress otsHashAddress)
		{
			int n = @params.getDigestSize();
			if (startHash == null)
			{
				throw new NullPointerException("startHash == null");
			}
			if (startHash.Length != n)
			{
				throw new IllegalArgumentException("startHash needs to be " + n + "bytes");
			}
			if (otsHashAddress == null)
			{
				throw new NullPointerException("otsHashAddress == null");
			}
			if (otsHashAddress.toByteArray() == null)
			{
				throw new NullPointerException("otsHashAddress byte array == null");
			}
			if ((startIndex + steps) > @params.getWinternitzParameter() - 1)
			{
				throw new IllegalArgumentException("max chain length must not be greater than w");
			}

			if (steps == 0)
			{
				return startHash;
			}

			byte[] tmp = chain(startHash, startIndex, steps - 1, otsHashAddress);
			otsHashAddress = (OTSHashAddress)(new OTSHashAddress.Builder()).withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress()).withOTSAddress(otsHashAddress.getOTSAddress()).withChainAddress(otsHashAddress.getChainAddress()).withHashAddress(startIndex + steps - 1).withKeyAndMask(0).build();
			byte[] key = khf.PRF(publicSeed, otsHashAddress.toByteArray());
			otsHashAddress = (OTSHashAddress)(new OTSHashAddress.Builder()).withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress()).withOTSAddress(otsHashAddress.getOTSAddress()).withChainAddress(otsHashAddress.getChainAddress()).withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(1).build();
			byte[] bitmask = khf.PRF(publicSeed, otsHashAddress.toByteArray());
			byte[] tmpMasked = new byte[n];
			for (int i = 0; i < n; i++)
			{
				tmpMasked[i] = (byte)(tmp[i] ^ bitmask[i]);
			}
			tmp = khf.F(key, tmpMasked);
			return tmp;
		}

		/// <summary>
		/// Obtain base w values from Input.
		/// </summary>
		/// <param name="messageDigest"> Input data. </param>
		/// <param name="w">             Base. </param>
		/// <param name="outLength">     Length of output. </param>
		/// <returns> outLength-length list of base w integers. </returns>
		private List<int> convertToBaseW(byte[] messageDigest, int w, int outLength)
		{
			if (messageDigest == null)
			{
				throw new NullPointerException("msg == null");
			}
			if (w != 4 && w != 16)
			{
				throw new IllegalArgumentException("w needs to be 4 or 16");
			}
			int logW = XMSSUtil.log2(w);
			if (outLength > ((8 * messageDigest.Length) / logW))
			{
				throw new IllegalArgumentException("outLength too big");
			}

			ArrayList<int> res = new ArrayList<int>();
			for (int i = 0; i < messageDigest.Length; i++)
			{
				for (int j = 8 - logW; j >= 0; j -= logW)
				{
					res.add((messageDigest[i] >> j) & (w - 1));
					if (res.size() == outLength)
					{
						return res;
					}
				}
			}
			return res;
		}

		/// <summary>
		/// Derive WOTS+ secret key for specific index as in XMSS ref impl Andreas
		/// Huelsing.
		/// </summary>
		/// <param name="otsHashAddress"> </param>
		/// <returns> WOTS+ secret key at index. </returns>
		public byte[] getWOTSPlusSecretKey(byte[] secretKeySeed, OTSHashAddress otsHashAddress)
		{
			otsHashAddress = (OTSHashAddress)(new OTSHashAddress.Builder()).withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress()).withOTSAddress(otsHashAddress.getOTSAddress()).build();
			return khf.PRF(secretKeySeed, otsHashAddress.toByteArray());
		}

		/// <summary>
		/// Derive private key at index from secret key seed.
		/// </summary>
		/// <param name="index"> Index. </param>
		/// <returns> Private key at index. </returns>
		private byte[] expandSecretKeySeed(int index)
		{
			if (index < 0 || index >= @params.getLen())
			{
				throw new IllegalArgumentException("index out of bounds");
			}
			return khf.PRF(secretKeySeed, XMSSUtil.toBytesBigEndian(index, 32));
		}

		/// <summary>
		/// Getter parameters.
		/// </summary>
		/// <returns> params. </returns>
		public WOTSPlusParameters getParams()
		{
			return @params;
		}

		/// <summary>
		/// Getter keyed hash functions.
		/// </summary>
		/// <returns> keyed hash functions. </returns>
		public KeyedHashFunctions getKhf()
		{
			return khf;
		}

		/// <summary>
		/// Getter secret key seed.
		/// </summary>
		/// <returns> secret key seed. </returns>
		public byte[] getSecretKeySeed()
		{
			return Arrays.clone(secretKeySeed);
		}

		/// <summary>
		/// Getter public seed.
		/// </summary>
		/// <returns> public seed. </returns>
		public byte[] getPublicSeed()
		{
			return Arrays.clone(publicSeed);
		}

		/// <summary>
		/// Getter private key.
		/// </summary>
		/// <returns> WOTS+ private key. </returns>
		public WOTSPlusPrivateKeyParameters getPrivateKey()
		{
			byte[][] privateKey = new byte[@params.getLen()][];
			for (int i = 0; i < privateKey.Length; i++)
			{
				privateKey[i] = expandSecretKeySeed(i);
			}
			return new WOTSPlusPrivateKeyParameters(@params, privateKey);
		}

		/// <summary>
		/// Calculates a new public key based on the state of secretKeySeed,
		/// publicSeed and otsHashAddress.
		/// </summary>
		/// <param name="otsHashAddress"> OTS hash address for randomization. </param>
		/// <returns> WOTS+ public key. </returns>
		public WOTSPlusPublicKeyParameters getPublicKey(OTSHashAddress otsHashAddress)
		{
			if (otsHashAddress == null)
			{
				throw new NullPointerException("otsHashAddress == null");
			}
			byte[][] publicKey = new byte[@params.getLen()][];
			/* derive public key from secretKeySeed */
			for (int i = 0; i < @params.getLen(); i++)
			{
				otsHashAddress = (OTSHashAddress)(new OTSHashAddress.Builder()).withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress()).withOTSAddress(otsHashAddress.getOTSAddress()).withChainAddress(i).withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask()).build();
				publicKey[i] = chain(expandSecretKeySeed(i), 0, @params.getWinternitzParameter() - 1, otsHashAddress);
			}
			return new WOTSPlusPublicKeyParameters(@params, publicKey);
		}
	}

}