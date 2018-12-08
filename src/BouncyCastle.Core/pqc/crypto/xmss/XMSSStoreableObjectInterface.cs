namespace org.bouncycastle.pqc.crypto.xmss
{
	/// <summary>
	/// Interface for XMSS objects that need to be storeable as a byte array.
	/// 
	/// </summary>
	public interface XMSSStoreableObjectInterface
	{

		/// <summary>
		/// Create byte representation of object.
		/// </summary>
		/// <returns> Byte representation of object. </returns>
		byte[] toByteArray();
	}

}