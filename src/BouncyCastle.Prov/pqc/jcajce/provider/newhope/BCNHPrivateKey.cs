using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider.newhope
{

	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using NHPrivateKeyParameters = org.bouncycastle.pqc.crypto.newhope.NHPrivateKeyParameters;
	using NHPrivateKey = org.bouncycastle.pqc.jcajce.interfaces.NHPrivateKey;
	using Arrays = org.bouncycastle.util.Arrays;
	using Pack = org.bouncycastle.util.Pack;

	public class BCNHPrivateKey : NHPrivateKey
	{
		private const long serialVersionUID = 1L;

		private readonly NHPrivateKeyParameters @params;

		public BCNHPrivateKey(NHPrivateKeyParameters @params)
		{
			this.@params = @params;
		}

		public BCNHPrivateKey(PrivateKeyInfo keyInfo)
		{
			this.@params = new NHPrivateKeyParameters(convert(ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets()));
		}

		/// <summary>
		/// Compare this NH private key with another object.
		/// </summary>
		/// <param name="o"> the other object </param>
		/// <returns> the result of the comparison </returns>
		public override bool Equals(object o)
		{
			if (o == null || !(o is BCNHPrivateKey))
			{
				return false;
			}
			BCNHPrivateKey otherKey = (BCNHPrivateKey)o;

			return Arrays.areEqual(@params.getSecData(), otherKey.@params.getSecData());
		}

		public override int GetHashCode()
		{
			return Arrays.GetHashCode(@params.getSecData());
		}

		/// <returns> name of the algorithm - "NH" </returns>
		public string getAlgorithm()
		{
			return "NH";
		}

		public virtual byte[] getEncoded()
		{
			PrivateKeyInfo pki;
			try
			{
				AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers_Fields.newHope);

				short[] privateKeyData = @params.getSecData();

				byte[] octets = new byte[privateKeyData.Length * 2];
				for (int i = 0; i != privateKeyData.Length; i++)
				{
					Pack.shortToLittleEndian(privateKeyData[i], octets, i * 2);
				}

				pki = new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(octets));

				return pki.getEncoded();
			}
			catch (IOException)
			{
				return null;
			}
		}

		public virtual string getFormat()
		{
			return "PKCS#8";
		}

		public virtual short[] getSecretData()
		{
			return @params.getSecData();
		}

		public virtual CipherParameters getKeyParams()
		{
			return @params;
		}

		private static short[] convert(byte[] octets)
		{
			short[] rv = new short[octets.Length / 2];

			for (int i = 0; i != rv.Length; i++)
			{
				rv[i] = Pack.littleEndianToShort(octets, i * 2);
			}

			return rv;
		}
	}

}