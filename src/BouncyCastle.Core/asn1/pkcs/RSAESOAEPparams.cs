using org.bouncycastle.asn1.oiw;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.pkcs
{
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public class RSAESOAEPparams : ASN1Object
	{
		private AlgorithmIdentifier hashAlgorithm;
		private AlgorithmIdentifier maskGenAlgorithm;
		private AlgorithmIdentifier pSourceAlgorithm;

		public static readonly AlgorithmIdentifier DEFAULT_HASH_ALGORITHM = new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1, DERNull.INSTANCE);
		public static readonly AlgorithmIdentifier DEFAULT_MASK_GEN_FUNCTION = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_mgf1, DEFAULT_HASH_ALGORITHM);
		public static readonly AlgorithmIdentifier DEFAULT_P_SOURCE_ALGORITHM = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_pSpecified, new DEROctetString(new byte[0]));

		public static RSAESOAEPparams getInstance(object obj)
		{
			if (obj is RSAESOAEPparams)
			{
				return (RSAESOAEPparams)obj;
			}
			else if (obj != null)
			{
				return new RSAESOAEPparams(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		/// <summary>
		/// The default version
		/// </summary>
		public RSAESOAEPparams()
		{
			hashAlgorithm = DEFAULT_HASH_ALGORITHM;
			maskGenAlgorithm = DEFAULT_MASK_GEN_FUNCTION;
			pSourceAlgorithm = DEFAULT_P_SOURCE_ALGORITHM;
		}

		public RSAESOAEPparams(AlgorithmIdentifier hashAlgorithm, AlgorithmIdentifier maskGenAlgorithm, AlgorithmIdentifier pSourceAlgorithm)
		{
			this.hashAlgorithm = hashAlgorithm;
			this.maskGenAlgorithm = maskGenAlgorithm;
			this.pSourceAlgorithm = pSourceAlgorithm;
		}

		/// @deprecated use getInstance() 
		/// <param name="seq"> </param>
		public RSAESOAEPparams(ASN1Sequence seq)
		{
			hashAlgorithm = DEFAULT_HASH_ALGORITHM;
			maskGenAlgorithm = DEFAULT_MASK_GEN_FUNCTION;
			pSourceAlgorithm = DEFAULT_P_SOURCE_ALGORITHM;

			for (int i = 0; i != seq.size(); i++)
			{
				ASN1TaggedObject o = (ASN1TaggedObject)seq.getObjectAt(i);

				switch (o.getTagNo())
				{
				case 0:
					hashAlgorithm = AlgorithmIdentifier.getInstance(o, true);
					break;
				case 1:
					maskGenAlgorithm = AlgorithmIdentifier.getInstance(o, true);
					break;
				case 2:
					pSourceAlgorithm = AlgorithmIdentifier.getInstance(o, true);
					break;
				default:
					throw new IllegalArgumentException("unknown tag");
				}
			}
		}

		public virtual AlgorithmIdentifier getHashAlgorithm()
		{
			return hashAlgorithm;
		}

		public virtual AlgorithmIdentifier getMaskGenAlgorithm()
		{
			return maskGenAlgorithm;
		}

		public virtual AlgorithmIdentifier getPSourceAlgorithm()
		{
			return pSourceAlgorithm;
		}

		/// <summary>
		/// <pre>
		///  RSAES-OAEP-params ::= SEQUENCE {
		///     hashAlgorithm      [0] OAEP-PSSDigestAlgorithms     DEFAULT sha1,
		///     maskGenAlgorithm   [1] PKCS1MGFAlgorithms  DEFAULT mgf1SHA1,
		///     pSourceAlgorithm   [2] PKCS1PSourceAlgorithms  DEFAULT pSpecifiedEmpty
		///   }
		/// 
		///   OAEP-PSSDigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
		///     { OID id-sha1 PARAMETERS NULL   }|
		///     { OID id-sha256 PARAMETERS NULL }|
		///     { OID id-sha384 PARAMETERS NULL }|
		///     { OID id-sha512 PARAMETERS NULL },
		///     ...  -- Allows for future expansion --
		///   }
		///   PKCS1MGFAlgorithms    ALGORITHM-IDENTIFIER ::= {
		///     { OID id-mgf1 PARAMETERS OAEP-PSSDigestAlgorithms },
		///    ...  -- Allows for future expansion --
		///   }
		///   PKCS1PSourceAlgorithms    ALGORITHM-IDENTIFIER ::= {
		///     { OID id-pSpecified PARAMETERS OCTET STRING },
		///     ...  -- Allows for future expansion --
		///  }
		/// </pre> </summary>
		/// <returns> the asn1 primitive representing the parameters. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (!hashAlgorithm.Equals(DEFAULT_HASH_ALGORITHM))
			{
				v.add(new DERTaggedObject(true, 0, hashAlgorithm));
			}

			if (!maskGenAlgorithm.Equals(DEFAULT_MASK_GEN_FUNCTION))
			{
				v.add(new DERTaggedObject(true, 1, maskGenAlgorithm));
			}

			if (!pSourceAlgorithm.Equals(DEFAULT_P_SOURCE_ALGORITHM))
			{
				v.add(new DERTaggedObject(true, 2, pSourceAlgorithm));
			}

			return new DERSequence(v);
		}
	}

}