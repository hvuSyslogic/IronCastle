using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.jcajce.spec
{

	using DERNull = org.bouncycastle.asn1.DERNull;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// Extension of PBEKeySpec which takes into account the PRF algorithm setting available in PKCS#5 PBKDF2.
	/// </summary>
	public class PBKDF2KeySpec : PBEKeySpec
	{
		private static readonly AlgorithmIdentifier defaultPRF = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_hmacWithSHA1, DERNull.INSTANCE);

		private AlgorithmIdentifier prf;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="password"> password to use as the seed of the PBE key generator. </param>
		/// <param name="salt"> salt to use in the generator, </param>
		/// <param name="iterationCount"> iteration count to use in the generator. </param>
		/// <param name="keySize"> size of the key to be generated (in bits). </param>
		/// <param name="prf"> identifier and parameters for the PRF algorithm to use. </param>
		public PBKDF2KeySpec(char[] password, byte[] salt, int iterationCount, int keySize, AlgorithmIdentifier prf) : base(password, salt, iterationCount, keySize)
		{

			this.prf = prf;
		}

		/// <summary>
		/// Return true if this spec is for the default PRF (HmacSHA1), false otherwise.
		/// </summary>
		/// <returns> true if this spec uses the default PRF, false otherwise. </returns>
		public virtual bool isDefaultPrf()
		{
			return defaultPRF.Equals(prf);
		}

		/// <summary>
		/// Return an AlgorithmIdentifier representing the PRF.
		/// </summary>
		/// <returns> the PRF's AlgorithmIdentifier. </returns>
		public virtual AlgorithmIdentifier getPrf()
		{
			return prf;
		}
	}

}