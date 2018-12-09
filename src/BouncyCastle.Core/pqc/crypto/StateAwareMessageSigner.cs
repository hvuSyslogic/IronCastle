﻿namespace org.bouncycastle.pqc.crypto
{

	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;

	/// <summary>
	/// Base interface for a PQC stateful signature algorithm.
	/// </summary>
	public interface StateAwareMessageSigner : MessageSigner
	{
		/// <summary>
		/// Return the current version of the private key with the updated state.
		/// <para>
		/// <b>Note:</b> calling this method will effectively disable the Signer from being used for further
		///  signature generation without another call to init().
		/// </para> </summary>
		/// <returns> an updated private key object, which can be used for later signature generation. </returns>
		AsymmetricKeyParameter getUpdatedPrivateKey();
	}

}