namespace org.bouncycastle.crypto.engines
{
	/// <summary>
	/// an implementation of the ARIA Key Wrapper from the NIST Key Wrap
	/// Specification.
	/// <para>
	/// For further details see: <a href="http://csrc.nist.gov/encryption/kms/key-wrap.pdf">http://csrc.nist.gov/encryption/kms/key-wrap.pdf</a>.
	/// </para>
	/// </summary>
	public class ARIAWrapEngine : RFC3394WrapEngine
	{
		/// <summary>
		/// Create a regular AESWrapEngine specifying the encrypt for wrapping, decrypt for unwrapping.
		/// </summary>
		public ARIAWrapEngine() : base(new ARIAEngine())
		{
		}

		/// <summary>
		/// Create an AESWrapEngine where the underlying cipher is set to decrypt for wrapping, encrypt for unwrapping.
		/// </summary>
		/// <param name="useReverseDirection"> true if underlying cipher should be used in decryption mode, false otherwise. </param>
		public ARIAWrapEngine(bool useReverseDirection) : base(new ARIAEngine(), useReverseDirection)
		{
		}
	}

}