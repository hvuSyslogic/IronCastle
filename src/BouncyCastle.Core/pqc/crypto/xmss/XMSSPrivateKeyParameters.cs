using System.IO;
using BouncyCastle.Core.Port.java.lang;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.pqc.crypto.xmss
{

			
	/// <summary>
	/// XMSS Private Key.
	/// </summary>
	public sealed class XMSSPrivateKeyParameters : AsymmetricKeyParameter, XMSSStoreableObjectInterface
	{

		/// <summary>
		/// XMSS parameters object.
		/// </summary>
		private readonly XMSSParameters @params;
		/// <summary>
		/// Secret for the derivation of WOTS+ secret keys.
		/// </summary>
		private readonly byte[] secretKeySeed;
		/// <summary>
		/// Secret for the randomization of message digests during signature
		/// creation.
		/// </summary>
		private readonly byte[] secretKeyPRF;
		/// <summary>
		/// Public seed for the randomization of hashes.
		/// </summary>
		private readonly byte[] publicSeed;
		/// <summary>
		/// Public root of binary tree.
		/// </summary>
		private readonly byte[] root;
		/// <summary>
		/// BDS state.
		/// </summary>
		private readonly BDS bdsState;

		private XMSSPrivateKeyParameters(Builder builder) : base(true)
		{
			@params = builder.@params;
			if (@params == null)
			{
				throw new NullPointerException("params == null");
			}
			int n = @params.getDigestSize();
			byte[] privateKey = builder.privateKey;
			if (privateKey != null)
			{
				if (builder.xmss == null)
				{
					throw new NullPointerException("xmss == null");
				}
				/* import */
				int height = @params.getHeight();
				int indexSize = 4;
				int secretKeySize = n;
				int secretKeyPRFSize = n;
				int publicSeedSize = n;
				int rootSize = n;
				/*
				int totalSize = indexSize + secretKeySize + secretKeyPRFSize + publicSeedSize + rootSize;
				if (privateKey.length != totalSize) {
					throw new ParseException("private key has wrong size", 0);
				}
				*/
				int position = 0;
				int index = Pack.bigEndianToInt(privateKey, position);
				if (!XMSSUtil.isIndexValid(height, index))
				{
					throw new IllegalArgumentException("index out of bounds");
				}
				position += indexSize;
				secretKeySeed = XMSSUtil.extractBytesAtOffset(privateKey, position, secretKeySize);
				position += secretKeySize;
				secretKeyPRF = XMSSUtil.extractBytesAtOffset(privateKey, position, secretKeyPRFSize);
				position += secretKeyPRFSize;
				publicSeed = XMSSUtil.extractBytesAtOffset(privateKey, position, publicSeedSize);
				position += publicSeedSize;
				root = XMSSUtil.extractBytesAtOffset(privateKey, position, rootSize);
				position += rootSize;
				/* import BDS state */
				byte[] bdsStateBinary = XMSSUtil.extractBytesAtOffset(privateKey, position, privateKey.Length - position);
				try
				{
					BDS bdsImport = (BDS)XMSSUtil.deserialize(bdsStateBinary, typeof(BDS));
					if (bdsImport.getIndex() != index)
					{
						throw new IllegalStateException("serialized BDS has wrong index");
					}
					bdsState = bdsImport.withWOTSDigest(DigestUtil.getDigestOID(builder.xmss.getDigest().getAlgorithmName()));
				}
				catch (IOException e)
				{
					throw new IllegalArgumentException(e.Message, e);
				}
				catch (ClassNotFoundException e)
				{
					throw new IllegalArgumentException(e.Message, e);
				}
			}
			else
			{
				/* set */
				byte[] tmpSecretKeySeed = builder.secretKeySeed;
				if (tmpSecretKeySeed != null)
				{
					if (tmpSecretKeySeed.Length != n)
					{
						throw new IllegalArgumentException("size of secretKeySeed needs to be equal size of digest");
					}
					secretKeySeed = tmpSecretKeySeed;
				}
				else
				{
					secretKeySeed = new byte[n];
				}
				byte[] tmpSecretKeyPRF = builder.secretKeyPRF;
				if (tmpSecretKeyPRF != null)
				{
					if (tmpSecretKeyPRF.Length != n)
					{
						throw new IllegalArgumentException("size of secretKeyPRF needs to be equal size of digest");
					}
					secretKeyPRF = tmpSecretKeyPRF;
				}
				else
				{
					secretKeyPRF = new byte[n];
				}
				byte[] tmpPublicSeed = builder.publicSeed;
				if (tmpPublicSeed != null)
				{
					if (tmpPublicSeed.Length != n)
					{
						throw new IllegalArgumentException("size of publicSeed needs to be equal size of digest");
					}
					publicSeed = tmpPublicSeed;
				}
				else
				{
					publicSeed = new byte[n];
				}
				byte[] tmpRoot = builder.root;
				if (tmpRoot != null)
				{
					if (tmpRoot.Length != n)
					{
						throw new IllegalArgumentException("size of root needs to be equal size of digest");
					}
					root = tmpRoot;
				}
				else
				{
					root = new byte[n];
				}
				BDS tmpBDSState = builder.bdsState;
				if (tmpBDSState != null)
				{
					bdsState = tmpBDSState;
				}
				else
				{
					if (builder.index < ((1 << @params.getHeight()) - 2) && tmpPublicSeed != null && tmpSecretKeySeed != null)
					{
						bdsState = new BDS(@params, tmpPublicSeed, tmpSecretKeySeed, (OTSHashAddress)(new OTSHashAddress.Builder()).build(), builder.index);
					}
					else
					{
						bdsState = new BDS(@params, builder.index);
					}
				}
			}
		}

		public class Builder
		{

			/* mandatory */
			internal readonly XMSSParameters @params;
			/* optional */
			internal int index = 0;
			internal byte[] secretKeySeed = null;
			internal byte[] secretKeyPRF = null;
			internal byte[] publicSeed = null;
			internal byte[] root = null;
			internal BDS bdsState = null;
			internal byte[] privateKey = null;
			internal XMSSParameters xmss = null;

			public Builder(XMSSParameters @params) : base()
			{
				this.@params = @params;
			}

			public virtual Builder withIndex(int val)
			{
				index = val;
				return this;
			}

			public virtual Builder withSecretKeySeed(byte[] val)
			{
				secretKeySeed = XMSSUtil.cloneArray(val);
				return this;
			}

			public virtual Builder withSecretKeyPRF(byte[] val)
			{
				secretKeyPRF = XMSSUtil.cloneArray(val);
				return this;
			}

			public virtual Builder withPublicSeed(byte[] val)
			{
				publicSeed = XMSSUtil.cloneArray(val);
				return this;
			}

			public virtual Builder withRoot(byte[] val)
			{
				root = XMSSUtil.cloneArray(val);
				return this;
			}

			public virtual Builder withBDSState(BDS valBDS)
			{
				bdsState = valBDS;
				return this;
			}

			public virtual Builder withPrivateKey(byte[] privateKeyVal, XMSSParameters xmssParameters)
			{
				privateKey = XMSSUtil.cloneArray(privateKeyVal);
				xmss = xmssParameters;
				return this;
			}

			public virtual XMSSPrivateKeyParameters build()
			{
				return new XMSSPrivateKeyParameters(this);
			}
		}

		public byte[] toByteArray()
		{
			/* index || secretKeySeed || secretKeyPRF || publicSeed || root */
			int n = @params.getDigestSize();
			int indexSize = 4;
			int secretKeySize = n;
			int secretKeyPRFSize = n;
			int publicSeedSize = n;
			int rootSize = n;
			int totalSize = indexSize + secretKeySize + secretKeyPRFSize + publicSeedSize + rootSize;
			byte[] @out = new byte[totalSize];
			int position = 0;
			/* copy index */
			Pack.intToBigEndian(bdsState.getIndex(), @out, position);
			position += indexSize;
			/* copy secretKeySeed */
			XMSSUtil.copyBytesAtOffset(@out, secretKeySeed, position);
			position += secretKeySize;
			/* copy secretKeyPRF */
			XMSSUtil.copyBytesAtOffset(@out, secretKeyPRF, position);
			position += secretKeyPRFSize;
			/* copy publicSeed */
			XMSSUtil.copyBytesAtOffset(@out, publicSeed, position);
			position += publicSeedSize;
			/* copy root */
			XMSSUtil.copyBytesAtOffset(@out, root, position);
			/* concatenate bdsState */
			byte[] bdsStateOut = null;
			try
			{
				bdsStateOut = XMSSUtil.serialize(bdsState);
			}
			catch (IOException e)
			{
				throw new RuntimeException("error serializing bds state: " + e.Message);
			}

			return Arrays.concatenate(@out, bdsStateOut);
		}

		public int getIndex()
		{
			return bdsState.getIndex();
		}

		public byte[] getSecretKeySeed()
		{
			return XMSSUtil.cloneArray(secretKeySeed);
		}

		public byte[] getSecretKeyPRF()
		{
			return XMSSUtil.cloneArray(secretKeyPRF);
		}

		public byte[] getPublicSeed()
		{
			return XMSSUtil.cloneArray(publicSeed);
		}

		public byte[] getRoot()
		{
			return XMSSUtil.cloneArray(root);
		}

		public BDS getBDSState()
		{
			return bdsState;
		}

		public XMSSParameters getParameters()
		{
			return @params;
		}

		public XMSSPrivateKeyParameters getNextKey()
		{
			/* prepare authentication path for next leaf */
			int treeHeight = this.@params.getHeight();
			if (this.getIndex() < ((1 << treeHeight) - 1))
			{
				return (new XMSSPrivateKeyParameters.Builder(@params)).withSecretKeySeed(secretKeySeed).withSecretKeyPRF(secretKeyPRF).withPublicSeed(publicSeed).withRoot(root).withBDSState(bdsState.getNextState(publicSeed, secretKeySeed, (OTSHashAddress)(new OTSHashAddress.Builder()).build())).build();
			}
			else
			{
				return (new XMSSPrivateKeyParameters.Builder(@params)).withSecretKeySeed(secretKeySeed).withSecretKeyPRF(secretKeyPRF).withPublicSeed(publicSeed).withRoot(root).withBDSState(new BDS(@params, getIndex() + 1)).build(); // no more nodes left.
			}
		}

	}

}