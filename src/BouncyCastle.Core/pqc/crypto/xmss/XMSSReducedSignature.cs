using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.pqc.crypto.xmss
{

	/// <summary>
	/// Reduced XMSS Signature.
	/// </summary>
	public class XMSSReducedSignature : XMSSStoreableObjectInterface
	{

		private readonly XMSSParameters @params;
		private readonly WOTSPlusSignature wotsPlusSignature;
		private readonly List<XMSSNode> authPath;

		public XMSSReducedSignature(Builder builder) : base()
		{
			@params = builder.@params;
			if (@params == null)
			{
				throw new NullPointerException("params == null");
			}
			int n = @params.getDigestSize();
			int len = @params.getWOTSPlus().getParams().getLen();
			int height = @params.getHeight();
			byte[] reducedSignature = builder.reducedSignature;
			if (reducedSignature != null)
			{
				/* import */
				int signatureSize = len * n;
				int authPathSize = height * n;
				int totalSize = signatureSize + authPathSize;
				if (reducedSignature.Length != totalSize)
				{
					throw new IllegalArgumentException("signature has wrong size");
				}
				int position = 0;
				byte[][] wotsPlusSignature = new byte[len][];
				for (int i = 0; i < wotsPlusSignature.Length; i++)
				{
					wotsPlusSignature[i] = XMSSUtil.extractBytesAtOffset(reducedSignature, position, n);
					position += n;
				}
				this.wotsPlusSignature = new WOTSPlusSignature(@params.getWOTSPlus().getParams(), wotsPlusSignature);

				List<XMSSNode> nodeList = new ArrayList<XMSSNode>();
				for (int i = 0; i < height; i++)
				{
					nodeList.add(new XMSSNode(i, XMSSUtil.extractBytesAtOffset(reducedSignature, position, n)));
					position += n;
				}
				authPath = nodeList;
			}
			else
			{
				/* set */
				WOTSPlusSignature tmpSignature = builder.wotsPlusSignature;
				if (tmpSignature != null)
				{
					wotsPlusSignature = tmpSignature;
				}
				else
				{
//JAVA TO C# CONVERTER NOTE: The following call to the 'RectangularArrays' helper class reproduces the rectangular array initialization that is automatic in Java:
//ORIGINAL LINE: wotsPlusSignature = new WOTSPlusSignature(params.getWOTSPlus().getParams(), new byte[len][n]);
					wotsPlusSignature = new WOTSPlusSignature(@params.getWOTSPlus().getParams(), RectangularArrays.ReturnRectangularSbyteArray(len, n));
				}
				List<XMSSNode> tmpAuthPath = builder.authPath;
				if (tmpAuthPath != null)
				{
					if (tmpAuthPath.size() != height)
					{
						throw new IllegalArgumentException("size of authPath needs to be equal to height of tree");
					}
					authPath = tmpAuthPath;
				}
				else
				{
					authPath = new ArrayList<XMSSNode>();
				}
			}
		}

		public class Builder
		{

			/* mandatory */
			internal readonly XMSSParameters @params;
			/* optional */
			internal WOTSPlusSignature wotsPlusSignature = null;
			internal List<XMSSNode> authPath = null;
			internal byte[] reducedSignature = null;

			public Builder(XMSSParameters @params) : base()
			{
				this.@params = @params;
			}

			public virtual Builder withWOTSPlusSignature(WOTSPlusSignature val)
			{
				wotsPlusSignature = val;
				return this;
			}

			public virtual Builder withAuthPath(List<XMSSNode> val)
			{
				authPath = val;
				return this;
			}

			public virtual Builder withReducedSignature(byte[] val)
			{
				reducedSignature = XMSSUtil.cloneArray(val);
				return this;
			}

			public virtual XMSSReducedSignature build()
			{
				return new XMSSReducedSignature(this);
			}
		}

		public virtual byte[] toByteArray()
		{
			/* signature || authentication path */
			int n = @params.getDigestSize();
			int signatureSize = @params.getWOTSPlus().getParams().getLen() * n;
			int authPathSize = @params.getHeight() * n;
			int totalSize = signatureSize + authPathSize;
			byte[] @out = new byte[totalSize];
			int position = 0;
			/* copy signature */
			byte[][] signature = this.wotsPlusSignature.toByteArray();
			for (int i = 0; i < signature.Length; i++)
			{
				XMSSUtil.copyBytesAtOffset(@out, signature[i], position);
				position += n;
			}
			/* copy authentication path */
			for (int i = 0; i < authPath.size(); i++)
			{
				byte[] value = authPath.get(i).getValue();
				XMSSUtil.copyBytesAtOffset(@out, value, position);
				position += n;
			}
			return @out;
		}

		public virtual XMSSParameters getParams()
		{
			return @params;
		}

		public virtual WOTSPlusSignature getWOTSPlusSignature()
		{
			return wotsPlusSignature;
		}

		public virtual List<XMSSNode> getAuthPath()
		{
			return authPath;
		}
	}

}