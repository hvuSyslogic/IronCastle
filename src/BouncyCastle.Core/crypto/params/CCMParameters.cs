namespace org.bouncycastle.crypto.@params
{
	/// @deprecated use AEADParameters 
	public class CCMParameters : AEADParameters
	{
		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="key"> key to be used by underlying cipher </param>
		/// <param name="macSize"> macSize in bits </param>
		/// <param name="nonce"> nonce to be used </param>
		/// <param name="associatedText"> associated text, if any </param>
		public CCMParameters(KeyParameter key, int macSize, byte[] nonce, byte[] associatedText) : base(key, macSize, nonce, associatedText)
		{
		}
	}

}