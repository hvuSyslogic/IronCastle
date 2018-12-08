namespace javax.crypto.spec
{

	/// <summary>
	/// This class specifies the set of parameters used with OAEP Padding, as defined
	/// in the PKCS #1 standard. Its ASN.1 definition in PKCS#1 standard is described
	/// below:
	/// 
	/// </pre>
	/// 
	/// RSAES-OAEP-params ::= SEQUENCE { hashAlgorithm [0] OAEP-PSSDigestAlgorithms
	/// DEFAULT sha1, maskGenAlgorithm [1] PKCS1MGFAlgorithms DEFAULT mgf1SHA1,
	/// pSourceAlgorithm [2] PKCS1PSourceAlgorithms DEFAULT pSpecifiedEmpty }
	/// 
	/// </pre>
	/// 
	/// where
	/// 
	/// <pre>
	/// 
	/// OAEP-PSSDigestAlgorithms ALGORITHM-IDENTIFIER ::= { { OID id-sha1 PARAMETERS
	/// NULL }| { OID id-sha256 PARAMETERS NULL }| { OID id-sha384 PARAMETERS NULL } | {
	/// OID id-sha512 PARAMETERS NULL }, ... -- Allows for future expansion -- }
	/// PKCS1MGFAlgorithms ALGORITHM-IDENTIFIER ::= { { OID id-mgf1 PARAMETERS
	/// OAEP-PSSDigestAlgorithms }, ... -- Allows for future expansion -- }
	/// PKCS1PSourceAlgorithms ALGORITHM-IDENTIFIER ::= { { OID id-pSpecified
	/// PARAMETERS OCTET STRING }, ... -- Allows for future expansion -- }
	/// 
	/// </pre>
	/// </summary>
	/// <seealso cref= PSource </seealso>
	public class OAEPParameterSpec : AlgorithmParameterSpec
	{
		private string mdName;
		private string mgfName;
		private AlgorithmParameterSpec mgfSpec;
		private PSource pSrc;

		/// <summary>
		/// Constructs a parameter set for OAEP padding as defined in the PKCS #1
		/// standard using the specified message digest algorithm mdName, mask
		/// generation function algorithm mgfName, parameters for the mask generation
		/// function mgfSpec, and source of the encoding input P pSrc.
		/// </summary>
		/// <param name="mdName"> the algorithm name for the message digest. </param>
		/// <param name="mgfName"> the algorithm name for the mask generation function. </param>
		/// <param name="mgfSpec"> the parameters for the mask generation function. If null is
		///            specified, null will be returned by getMGFParameters(). </param>
		/// <param name="pSrc"> the source of the encoding input P. </param>
		/// <exception cref="NullPointerException">  if mdName, mgfName, or pSrc is null. </exception>
		public OAEPParameterSpec(string mdName, string mgfName, AlgorithmParameterSpec mgfSpec, PSource pSrc)
		{
			this.mdName = mdName;
			this.mgfName = mgfName;
			this.mgfSpec = mgfSpec;
			this.pSrc = pSrc;
		}

		/// <summary>
		/// Returns the message digest algorithm name.
		/// </summary>
		/// <returns> the message digest algorithm name. </returns>
		public virtual string getDigestAlgorithm()
		{
			return mdName;
		}

		/// <summary>
		/// Returns the mask generation function algorithm name.
		/// </summary>
		/// <returns> the mask generation function algorithm name. </returns>
		public virtual string getMGFAlgorithm()
		{
			return mgfName;
		}

		/// <summary>
		/// Returns the parameters for the mask generation function.
		/// </summary>
		/// <returns> the parameters for the mask generation function. </returns>
		public virtual AlgorithmParameterSpec getMGFParameters()
		{
			return mgfSpec;
		}

		/// <summary>
		/// Returns the source of encoding input P.
		/// </summary>
		/// <returns> the source of encoding input P. </returns>
		public virtual PSource getPSource()
		{
			return pSrc;
		}
	}

}