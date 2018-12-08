using System;

namespace org.bouncycastle.pqc.crypto.xmss
{

	/// <summary>
	/// Binary tree node.
	/// </summary>
	[Serializable]
	public sealed class XMSSNode
	{

		private const long serialVersionUID = 1L;

		private readonly int height;
		private readonly byte[] value;

		public XMSSNode(int height, byte[] value) : base()
		{
			this.height = height;
			this.value = value;
		}

		public int getHeight()
		{
			return height;
		}

		public byte[] getValue()
		{
			return XMSSUtil.cloneArray(value);
		}

		public XMSSNode clone()
		{
			return new XMSSNode(getHeight(), getValue());
		}
	}

}