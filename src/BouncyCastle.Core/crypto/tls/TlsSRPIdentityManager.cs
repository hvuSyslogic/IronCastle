namespace org.bouncycastle.crypto.tls
{
	public interface TlsSRPIdentityManager
	{
		/// <summary>
		/// Lookup the <seealso cref="TlsSRPLoginParameters"/> corresponding to the specified identity.
		/// 
		/// NOTE: To avoid "identity probing", unknown identities SHOULD be handled as recommended in RFC
		/// 5054 2.5.1.3. <seealso cref="SimulatedTlsSRPIdentityManager"/> is provided for this purpose.
		/// </summary>
		/// <param name="identity">
		///            the SRP identity sent by the connecting client </param>
		/// <returns> the <seealso cref="TlsSRPLoginParameters"/> for the specified identity, or else 'simulated'
		///         parameters if the identity is not recognized. A null value is also allowed, but not
		///         recommended. </returns>
		TlsSRPLoginParameters getLoginParameters(byte[] identity);
	}

}