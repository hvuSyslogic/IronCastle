using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.crypto.xmss
{
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;

	/// <summary>
	/// XMSS Public Key.
	/// </summary>
	public sealed class XMSSPublicKeyParameters : AsymmetricKeyParameter, XMSSStoreableObjectInterface
	{

		/// <summary>
		/// XMSS parameters object.
		/// </summary>
		private readonly XMSSParameters @params;
		//private final int oid;
		private readonly byte[] root;
		private readonly byte[] publicSeed;

		private XMSSPublicKeyParameters(Builder builder) : base(false)
		{
			@params = builder.@params;
			if (@params == null)
			{
				throw new NullPointerException("params == null");
			}
			int n = @params.getDigestSize();
			byte[] publicKey = builder.publicKey;
			if (publicKey != null)
			{
				/* import */
				// int oidSize = 4;
				int rootSize = n;
				int publicSeedSize = n;
				// int totalSize = oidSize + rootSize + publicSeedSize;
				int totalSize = rootSize + publicSeedSize;
				if (publicKey.Length != totalSize)
				{
					throw new IllegalArgumentException("public key has wrong size");
				}
				int position = 0;
				/*
				 * oid = XMSSUtil.bytesToIntBigEndian(publicKey, position); if (oid !=
				 * xmss.getParams().getOid().getOid()) { throw new
				 * ParseException("public key not compatible with current instance parameters"
				 * , 0); } position += oidSize;
				 */
				root = XMSSUtil.extractBytesAtOffset(publicKey, position, rootSize);
				position += rootSize;
				publicSeed = XMSSUtil.extractBytesAtOffset(publicKey, position, publicSeedSize);
			}
			else
			{
				/* set */
				byte[] tmpRoot = builder.root;
				if (tmpRoot != null)
				{
					if (tmpRoot.Length != n)
					{
						throw new IllegalArgumentException("length of root must be equal to length of digest");
					}
					root = tmpRoot;
				}
				else
				{
					root = new byte[n];
				}
				byte[] tmpPublicSeed = builder.publicSeed;
				if (tmpPublicSeed != null)
				{
					if (tmpPublicSeed.Length != n)
					{
						throw new IllegalArgumentException("length of publicSeed must be equal to length of digest");
					}
					publicSeed = tmpPublicSeed;
				}
				else
				{
					publicSeed = new byte[n];
				}
			}
		}

		public class Builder
		{

			/* mandatory */
			internal readonly XMSSParameters @params;
			/* optional */
			internal byte[] root = null;
			internal byte[] publicSeed = null;
			internal byte[] publicKey = null;

			public Builder(XMSSParameters @params) : base()
			{
				this.@params = @params;
			}

			public virtual Builder withRoot(byte[] val)
			{
				root = XMSSUtil.cloneArray(val);
				return this;
			}

			public virtual Builder withPublicSeed(byte[] val)
			{
				publicSeed = XMSSUtil.cloneArray(val);
				return this;
			}

			public virtual Builder withPublicKey(byte[] val)
			{
				publicKey = XMSSUtil.cloneArray(val);
				return this;
			}

			public virtual XMSSPublicKeyParameters build()
			{
				return new XMSSPublicKeyParameters(this);
			}
		}

		public byte[] toByteArray()
		{
			/* oid || root || seed */
			int n = @params.getDigestSize();
			// int oidSize = 4;
			int rootSize = n;
			int publicSeedSize = n;
			// int totalSize = oidSize + rootSize + publicSeedSize;
			int totalSize = rootSize + publicSeedSize;
			byte[] @out = new byte[totalSize];
			int position = 0;
			/* copy oid */
			/*
			 * XMSSUtil.intToBytesBigEndianOffset(out, oid, position); position +=
			 * oidSize;
			 */
			/* copy root */
			XMSSUtil.copyBytesAtOffset(@out, root, position);
			position += rootSize;
			/* copy public seed */
			XMSSUtil.copyBytesAtOffset(@out, publicSeed, position);
			return @out;
		}

		public byte[] getRoot()
		{
			return XMSSUtil.cloneArray(root);
		}

		public byte[] getPublicSeed()
		{
			return XMSSUtil.cloneArray(publicSeed);
		}

		public XMSSParameters getParameters()
		{
			 return @params;
		}
	}

}