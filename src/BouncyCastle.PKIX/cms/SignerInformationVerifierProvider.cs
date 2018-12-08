namespace org.bouncycastle.cms
{
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;

	public interface SignerInformationVerifierProvider
	{
		/// <summary>
		/// Return a SignerInformationVerifierProvider suitable for the passed in SID.
		/// </summary>
		/// <param name="sid"> the SignerId we are trying to match for. </param>
		/// <returns>  a verifier if one is available, null otherwise. </returns>
		/// <exception cref="OperatorCreationException"> if creation of the verifier fails when it should suceed. </exception>
		SignerInformationVerifier get(SignerId sid);
	}

}