namespace org.bouncycastle.gpg.keybox
{
	/// <summary>
	/// Base interface for a blob integrity checking operator.
	/// </summary>
	public interface BlobVerifier
	{
		/// <summary>
		/// Return true if the passed in blobData calculates to the expected digest.
		/// </summary>
		/// <param name="blobData">   bytes making up the blob. </param>
		/// <param name="blobDigest"> the expected digest. </param>
		/// <returns> true on a match, false otherwise. </returns>
		bool isMatched(byte[] blobData, byte[] blobDigest);
	}

}