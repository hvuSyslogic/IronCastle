using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.pqc.crypto.xmss
{
	
	/// <summary>
	/// XMSS Signature.
	/// </summary>
	public sealed class XMSSSignature : XMSSReducedSignature, XMSSStoreableObjectInterface
	{

		private readonly int index;
		private readonly byte[] random;

		private XMSSSignature(Builder builder) : base(builder)
		{
			index = builder.index;
			int n = getParams().getDigestSize();
			byte[] tmpRandom = builder.random;
			if (tmpRandom != null)
			{
				if (tmpRandom.Length != n)
				{
					throw new IllegalArgumentException("size of random needs to be equal to size of digest");
				}
				random = tmpRandom;
			}
			else
			{
				random = new byte[n];
			}
		}

		public class Builder : XMSSReducedSignature.Builder
		{

			internal readonly XMSSParameters @params;
			/* optional */
			internal int index = 0;
			internal byte[] random = null;

			public Builder(XMSSParameters @params) : base(@params)
			{
				this.@params = @params;
			}

			public virtual Builder withIndex(int val)
			{
				index = val;
				return this;
			}

			public virtual Builder withRandom(byte[] val)
			{
				random = XMSSUtil.cloneArray(val);
				return this;
			}

			public virtual Builder withSignature(byte[] val)
			{
				if (val == null)
				{
					throw new NullPointerException("signature == null");
				}
				int n = @params.getDigestSize();
				int len = @params.getWOTSPlus().getParams().getLen();
				int height = @params.getHeight();
				int indexSize = 4;
				int randomSize = n;
				int signatureSize = len * n;
				int authPathSize = height * n;
				int position = 0;
				/* extract index */
				index = Pack.bigEndianToInt(val, position);
				position += indexSize;
				/* extract random */
				random = XMSSUtil.extractBytesAtOffset(val, position, randomSize);
				position += randomSize;
				withReducedSignature(XMSSUtil.extractBytesAtOffset(val, position, signatureSize + authPathSize));
				return this;
			}

			public override XMSSSignature build()
			{
				return new XMSSSignature(this);
			}
		}

		public override byte[] toByteArray()
		{
			/* index || random || signature || authentication path */
			int n = getParams().getDigestSize();
			int indexSize = 4;
			int randomSize = n;
			int signatureSize = getParams().getWOTSPlus().getParams().getLen() * n;
			int authPathSize = getParams().getHeight() * n;
			int totalSize = indexSize + randomSize + signatureSize + authPathSize;
			byte[] @out = new byte[totalSize];
			int position = 0;
			/* copy index */
			Pack.intToBigEndian(index, @out, position);
			position += indexSize;
			/* copy random */
			XMSSUtil.copyBytesAtOffset(@out, random, position);
			position += randomSize;
			/* copy signature */
			byte[][] signature = getWOTSPlusSignature().toByteArray();
			for (int i = 0; i < signature.Length; i++)
			{
				XMSSUtil.copyBytesAtOffset(@out, signature[i], position);
				position += n;
			}
			/* copy authentication path */
			for (int i = 0; i < getAuthPath().size(); i++)
			{
				byte[] value = getAuthPath().get(i).getValue();
				XMSSUtil.copyBytesAtOffset(@out, value, position);
				position += n;
			}
			return @out;
		}

		public int getIndex()
		{
			return index;
		}

		public byte[] getRandom()
		{
			return XMSSUtil.cloneArray(random);
		}
	}

}