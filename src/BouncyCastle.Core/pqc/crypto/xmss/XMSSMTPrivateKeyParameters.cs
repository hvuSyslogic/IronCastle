﻿using System.IO;
using BouncyCastle.Core.Port.java.lang;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.pqc.crypto.xmss
{

		
	/// <summary>
	/// XMSS^MT Private Key.
	/// </summary>
	public sealed class XMSSMTPrivateKeyParameters : AsymmetricKeyParameter, XMSSStoreableObjectInterface
	{

		private readonly XMSSMTParameters @params;
		private readonly long index;
		private readonly byte[] secretKeySeed;
		private readonly byte[] secretKeyPRF;
		private readonly byte[] publicSeed;
		private readonly byte[] root;
		private readonly BDSStateMap bdsState;

		private XMSSMTPrivateKeyParameters(Builder builder) : base(true)
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
				int totalHeight = @params.getHeight();
				int indexSize = (totalHeight + 7) / 8;
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
				index = XMSSUtil.bytesToXBigEndian(privateKey, position, indexSize);
				if (!XMSSUtil.isIndexValid(totalHeight, index))
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
					BDSStateMap bdsImport = (BDSStateMap)XMSSUtil.deserialize(bdsStateBinary, typeof(BDSStateMap));

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
				index = builder.index;
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
				BDSStateMap tmpBDSState = builder.bdsState;
				if (tmpBDSState != null)
				{
					bdsState = tmpBDSState;
				}
				else
				{
					long globalIndex = builder.index;
					int totalHeight = @params.getHeight();

					if (XMSSUtil.isIndexValid(totalHeight, globalIndex) && tmpPublicSeed != null && tmpSecretKeySeed != null)
					{
						bdsState = new BDSStateMap(@params, builder.index, tmpPublicSeed, tmpSecretKeySeed);
					}
					else
					{
						bdsState = new BDSStateMap();
					}
				}
			}
		}

		public class Builder
		{

			/* mandatory */
			internal readonly XMSSMTParameters @params;
			/* optional */
			internal long index = 0L;
			internal byte[] secretKeySeed = null;
			internal byte[] secretKeyPRF = null;
			internal byte[] publicSeed = null;
			internal byte[] root = null;
			internal BDSStateMap bdsState = null;
			internal byte[] privateKey = null;
			internal XMSSParameters xmss = null;

			public Builder(XMSSMTParameters @params) : base()
			{
				this.@params = @params;
			}

			public virtual Builder withIndex(long val)
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

			public virtual Builder withBDSState(BDSStateMap val)
			{
				bdsState = val;
				return this;
			}

			public virtual Builder withPrivateKey(byte[] privateKeyVal, XMSSParameters xmssVal)
			{
				privateKey = XMSSUtil.cloneArray(privateKeyVal);
				xmss = xmssVal;
				return this;
			}

			public virtual XMSSMTPrivateKeyParameters build()
			{
				return new XMSSMTPrivateKeyParameters(this);
			}
		}

		public byte[] toByteArray()
		{
			/* index || secretKeySeed || secretKeyPRF || publicSeed || root */
			int n = @params.getDigestSize();
			int indexSize = (@params.getHeight() + 7) / 8;
			int secretKeySize = n;
			int secretKeyPRFSize = n;
			int publicSeedSize = n;
			int rootSize = n;
			int totalSize = indexSize + secretKeySize + secretKeyPRFSize + publicSeedSize + rootSize;
			byte[] @out = new byte[totalSize];
			int position = 0;
			/* copy index */
			byte[] indexBytes = XMSSUtil.toBytesBigEndian(index, indexSize);
			XMSSUtil.copyBytesAtOffset(@out, indexBytes, position);
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
			try
			{
				return Arrays.concatenate(@out, XMSSUtil.serialize(bdsState));
			}
			catch (IOException e)
			{
				throw new IllegalStateException("error serializing bds state: " + e.Message, e);
			}
		}

		public long getIndex()
		{
			return index;
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

		public BDSStateMap getBDSState()
		{
			return bdsState;
		}

		public XMSSMTParameters getParameters()
		{
			return @params;
		}

		public XMSSMTPrivateKeyParameters getNextKey()
		{
			BDSStateMap newState = new BDSStateMap(bdsState, @params, this.getIndex(), publicSeed, secretKeySeed);

			return (new XMSSMTPrivateKeyParameters.Builder(@params)).withIndex(index + 1).withSecretKeySeed(secretKeySeed).withSecretKeyPRF(secretKeyPRF).withPublicSeed(publicSeed).withRoot(root).withBDSState(newState).build();
		}
	}

}