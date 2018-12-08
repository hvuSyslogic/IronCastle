namespace org.bouncycastle.asn1
{
	/// <summary>
	/// General interface implemented by ASN.1 STRING objects for extracting the content String.
	/// </summary>
	public interface ASN1String
	{
		/// <summary>
		/// Return a Java String representation of this STRING type's content. </summary>
		/// <returns> a Java String representation of this STRING. </returns>
		string getString();
	}

}