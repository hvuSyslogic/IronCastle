using System;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.pqc.crypto.xmss
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// XMSS^MT Signature.
	/// </summary>
	public sealed class XMSSMTSignature : XMSSStoreableObjectInterface
	{

		private readonly XMSSMTParameters @params;
		private readonly long index;
		private readonly byte[] random;
		private readonly List<XMSSReducedSignature> reducedSignatures;

		private XMSSMTSignature(Builder builder) : base()
		{
			@params = builder.@params;
			if (@params == null)
			{
				throw new NullPointerException("params == null");
			}
			int n = @params.getDigestSize();
			byte[] signature = builder.signature;
			if (signature != null)
			{
				/* import */
				int len = @params.getWOTSPlus().getParams().getLen();
				int indexSize = (int)Math.Ceiling(@params.getHeight() / (double)8);
				int randomSize = n;
				int reducedSignatureSizeSingle = ((@params.getHeight() / @params.getLayers()) + len) * n;
				int reducedSignaturesSizeTotal = reducedSignatureSizeSingle * @params.getLayers();
				int totalSize = indexSize + randomSize + reducedSignaturesSizeTotal;
				if (signature.Length != totalSize)
				{
					throw new IllegalArgumentException("signature has wrong size");
				}
				int position = 0;
				index = XMSSUtil.bytesToXBigEndian(signature, position, indexSize);
				if (!XMSSUtil.isIndexValid(@params.getHeight(), index))
				{
					throw new IllegalArgumentException("index out of bounds");
				}
				position += indexSize;
				random = XMSSUtil.extractBytesAtOffset(signature, position, randomSize);
				position += randomSize;
				reducedSignatures = new ArrayList<XMSSReducedSignature>();
				while (position < signature.Length)
				{
					XMSSReducedSignature xmssSig = (new XMSSReducedSignature.Builder(@params.getXMSSParameters())).withReducedSignature(XMSSUtil.extractBytesAtOffset(signature, position, reducedSignatureSizeSingle)).build();
					reducedSignatures.add(xmssSig);
					position += reducedSignatureSizeSingle;
				}
			}
			else
			{
				/* set */
				index = builder.index;
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
				List<XMSSReducedSignature> tmpReducedSignatures = builder.reducedSignatures;
				if (tmpReducedSignatures != null)
				{
					reducedSignatures = tmpReducedSignatures;
				}
				else
				{
					reducedSignatures = new ArrayList<XMSSReducedSignature>();
				}
			}
		}

		public class Builder
		{

			/* mandatory */
			internal readonly XMSSMTParameters @params;
			/* optional */
			internal long index = 0L;
			internal byte[] random = null;
			internal List<XMSSReducedSignature> reducedSignatures = null;
			internal byte[] signature = null;

			public Builder(XMSSMTParameters @params) : base()
			{
				this.@params = @params;
			}

			public virtual Builder withIndex(long val)
			{
				index = val;
				return this;
			}

			public virtual Builder withRandom(byte[] val)
			{
				random = XMSSUtil.cloneArray(val);
				return this;
			}

			public virtual Builder withReducedSignatures(List<XMSSReducedSignature> val)
			{
				reducedSignatures = val;
				return this;
			}

			public virtual Builder withSignature(byte[] val)
			{
				signature = Arrays.clone(val);
				return this;
			}

			public virtual XMSSMTSignature build()
			{
				return new XMSSMTSignature(this);
			}
		}

		public byte[] toByteArray()
		{
			/* index || random || reduced signatures */
			int n = @params.getDigestSize();
			int len = @params.getWOTSPlus().getParams().getLen();
			int indexSize = (int)Math.Ceiling(@params.getHeight() / (double)8);
			int randomSize = n;
			int reducedSignatureSizeSingle = ((@params.getHeight() / @params.getLayers()) + len) * n;
			int reducedSignaturesSizeTotal = reducedSignatureSizeSingle * @params.getLayers();
			int totalSize = indexSize + randomSize + reducedSignaturesSizeTotal;
			byte[] @out = new byte[totalSize];
			int position = 0;
			/* copy index */
			byte[] indexBytes = XMSSUtil.toBytesBigEndian(index, indexSize);
			XMSSUtil.copyBytesAtOffset(@out, indexBytes, position);
			position += indexSize;
			/* copy random */
			XMSSUtil.copyBytesAtOffset(@out, random, position);
			position += randomSize;
			/* copy reduced signatures */
			foreach (XMSSReducedSignature reducedSignature in reducedSignatures)
			{
				byte[] signature = reducedSignature.toByteArray();
				XMSSUtil.copyBytesAtOffset(@out, signature, position);
				position += reducedSignatureSizeSingle;
			}
			return @out;
		}

		public long getIndex()
		{
			return index;
		}

		public byte[] getRandom()
		{
			return XMSSUtil.cloneArray(random);
		}

		public List<XMSSReducedSignature> getReducedSignatures()
		{
			return reducedSignatures;
		}
	}

}