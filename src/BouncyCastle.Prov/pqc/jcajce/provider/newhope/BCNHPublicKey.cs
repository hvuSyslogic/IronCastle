using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider.newhope
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using NHPublicKeyParameters = org.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;
	using NHPublicKey = org.bouncycastle.pqc.jcajce.interfaces.NHPublicKey;
	using Arrays = org.bouncycastle.util.Arrays;

	public class BCNHPublicKey : NHPublicKey
	{
		private const long serialVersionUID = 1L;

		private readonly NHPublicKeyParameters @params;

		public BCNHPublicKey(NHPublicKeyParameters @params)
		{
			this.@params = @params;
		}

		public BCNHPublicKey(SubjectPublicKeyInfo keyInfo)
		{
			this.@params = new NHPublicKeyParameters(keyInfo.getPublicKeyData().getBytes());
		}

		/// <summary>
		/// Compare this SPHINCS-256 public key with another object.
		/// </summary>
		/// <param name="o"> the other object </param>
		/// <returns> the result of the comparison </returns>
		public override bool Equals(object o)
		{
			if (o == null || !(o is BCNHPublicKey))
			{
				return false;
			}
			BCNHPublicKey otherKey = (BCNHPublicKey)o;

			return Arrays.areEqual(@params.getPubData(), otherKey.@params.getPubData());
		}

		public override int GetHashCode()
		{
			return Arrays.GetHashCode(@params.getPubData());
		}

		/// <returns> name of the algorithm - "NH" </returns>
		public string getAlgorithm()
		{
			return "NH";
		}

		public virtual byte[] getEncoded()
		{
			SubjectPublicKeyInfo pki;
			try
			{
				AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers_Fields.newHope);
				pki = new SubjectPublicKeyInfo(algorithmIdentifier, @params.getPubData());

				return pki.getEncoded();
			}
			catch (IOException)
			{
				return null;
			}
		}

		public virtual string getFormat()
		{
			return "X.509";
		}

		public virtual byte[] getPublicData()
		{
			return @params.getPubData();
		}

		public virtual CipherParameters getKeyParams()
		{
			return @params;
		}
	}

}