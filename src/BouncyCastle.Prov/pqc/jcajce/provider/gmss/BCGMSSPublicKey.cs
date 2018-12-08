using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider.gmss
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using GMSSPublicKey = org.bouncycastle.pqc.asn1.GMSSPublicKey;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using ParSet = org.bouncycastle.pqc.asn1.ParSet;
	using GMSSParameters = org.bouncycastle.pqc.crypto.gmss.GMSSParameters;
	using GMSSPublicKeyParameters = org.bouncycastle.pqc.crypto.gmss.GMSSPublicKeyParameters;
	using KeyUtil = org.bouncycastle.pqc.jcajce.provider.util.KeyUtil;
	using Hex = org.bouncycastle.util.encoders.Hex;

	/// <summary>
	/// This class implements the GMSS public key and is usually initiated by the <a
	/// href="GMSSKeyPairGenerator">GMSSKeyPairGenerator</a>.
	/// </summary>
	/// <seealso cref= org.bouncycastle.pqc.crypto.gmss.GMSSKeyPairGenerator </seealso>
	public class BCGMSSPublicKey : CipherParameters, PublicKey
	{

		/// 
		private const long serialVersionUID = 1L;

		/// <summary>
		/// The GMSS public key
		/// </summary>
		private byte[] publicKeyBytes;

		/// <summary>
		/// The GMSSParameterSet
		/// </summary>
		private GMSSParameters gmssParameterSet;


		private GMSSParameters gmssParams;

		/// <summary>
		/// The constructor
		/// </summary>
		/// <param name="pub">              a raw GMSS public key </param>
		/// <param name="gmssParameterSet"> an instance of GMSS Parameterset </param>
		/// <seealso cref= org.bouncycastle.pqc.crypto.gmss.GMSSKeyPairGenerator </seealso>
		public BCGMSSPublicKey(byte[] pub, GMSSParameters gmssParameterSet)
		{
			this.gmssParameterSet = gmssParameterSet;
			this.publicKeyBytes = pub;
		}

		public BCGMSSPublicKey(GMSSPublicKeyParameters @params) : this(@params.getPublicKey(), @params.getParameters())
		{
		}

		/// <summary>
		/// Returns the name of the algorithm
		/// </summary>
		/// <returns> "GMSS" </returns>
		public virtual string getAlgorithm()
		{
			return "GMSS";
		}

		/// <returns> The GMSS public key byte array </returns>
		public virtual byte[] getPublicKeyBytes()
		{
			return publicKeyBytes;
		}

		/// <returns> The GMSS Parameterset </returns>
		public virtual GMSSParameters getParameterSet()
		{
			return gmssParameterSet;
		}

		/// <summary>
		/// Returns a human readable form of the GMSS public key
		/// </summary>
		/// <returns> A human readable form of the GMSS public key </returns>
		public override string ToString()
		{
			string @out = "GMSS public key : "
				+ StringHelper.NewString(Hex.encode(publicKeyBytes)) + "\n"
				+ "Height of Trees: \n";

			for (int i = 0; i < gmssParameterSet.getHeightOfTrees().Length; i++)
			{
				@out = @out + "Layer " + i + " : "
					+ gmssParameterSet.getHeightOfTrees()[i] + " WinternitzParameter: "
					+ gmssParameterSet.getWinternitzParameter()[i] + " K: "
					+ gmssParameterSet.getK()[i] + "\n";
			}
			return @out;
		}

		public virtual byte[] getEncoded()
		{
			return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers_Fields.gmss, (new ParSet(gmssParameterSet.getNumOfLayers(), gmssParameterSet.getHeightOfTrees(), gmssParameterSet.getWinternitzParameter(), gmssParameterSet.getK())).toASN1Primitive()), new GMSSPublicKey(publicKeyBytes));
		}

		public virtual string getFormat()
		{
			return "X.509";
		}
	}

}