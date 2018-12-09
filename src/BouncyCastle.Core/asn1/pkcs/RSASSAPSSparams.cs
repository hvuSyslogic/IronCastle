﻿using BouncyCastle.Core.Port;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.pkcs
{

	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public class RSASSAPSSparams : ASN1Object
	{
		private AlgorithmIdentifier hashAlgorithm;
		private AlgorithmIdentifier maskGenAlgorithm;
		private ASN1Integer saltLength;
		private ASN1Integer trailerField;

		public static readonly AlgorithmIdentifier DEFAULT_HASH_ALGORITHM = new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1, DERNull.INSTANCE);
		public static readonly AlgorithmIdentifier DEFAULT_MASK_GEN_FUNCTION = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_mgf1, DEFAULT_HASH_ALGORITHM);
		public static readonly ASN1Integer DEFAULT_SALT_LENGTH = new ASN1Integer(20);
		public static readonly ASN1Integer DEFAULT_TRAILER_FIELD = new ASN1Integer(1);

		public static RSASSAPSSparams getInstance(object obj)
		{
			if (obj is RSASSAPSSparams)
			{
				return (RSASSAPSSparams)obj;
			}
			else if (obj != null)
			{
				return new RSASSAPSSparams(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		/// <summary>
		/// The default version
		/// </summary>
		public RSASSAPSSparams()
		{
			hashAlgorithm = DEFAULT_HASH_ALGORITHM;
			maskGenAlgorithm = DEFAULT_MASK_GEN_FUNCTION;
			saltLength = DEFAULT_SALT_LENGTH;
			trailerField = DEFAULT_TRAILER_FIELD;
		}

		public RSASSAPSSparams(AlgorithmIdentifier hashAlgorithm, AlgorithmIdentifier maskGenAlgorithm, ASN1Integer saltLength, ASN1Integer trailerField)
		{
			this.hashAlgorithm = hashAlgorithm;
			this.maskGenAlgorithm = maskGenAlgorithm;
			this.saltLength = saltLength;
			this.trailerField = trailerField;
		}

		private RSASSAPSSparams(ASN1Sequence seq)
		{
			hashAlgorithm = DEFAULT_HASH_ALGORITHM;
			maskGenAlgorithm = DEFAULT_MASK_GEN_FUNCTION;
			saltLength = DEFAULT_SALT_LENGTH;
			trailerField = DEFAULT_TRAILER_FIELD;

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
					saltLength = ASN1Integer.getInstance(o, true);
					break;
				case 3:
					trailerField = ASN1Integer.getInstance(o, true);
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

		public virtual BigInteger getSaltLength()
		{
			return saltLength.getValue();
		}

		public virtual BigInteger getTrailerField()
		{
			return trailerField.getValue();
		}

		/// <summary>
		/// <pre>
		/// RSASSA-PSS-params ::= SEQUENCE {
		///   hashAlgorithm      [0] OAEP-PSSDigestAlgorithms  DEFAULT sha1,
		///    maskGenAlgorithm   [1] PKCS1MGFAlgorithms  DEFAULT mgf1SHA1,
		///    saltLength         [2] INTEGER  DEFAULT 20,
		///    trailerField       [3] TrailerField  DEFAULT trailerFieldBC
		///  }
		/// 
		/// OAEP-PSSDigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
		///    { OID id-sha1 PARAMETERS NULL   }|
		///    { OID id-sha256 PARAMETERS NULL }|
		///    { OID id-sha384 PARAMETERS NULL }|
		///    { OID id-sha512 PARAMETERS NULL },
		///    ...  -- Allows for future expansion --
		/// }
		/// 
		/// PKCS1MGFAlgorithms    ALGORITHM-IDENTIFIER ::= {
		///   { OID id-mgf1 PARAMETERS OAEP-PSSDigestAlgorithms },
		///    ...  -- Allows for future expansion --
		/// }
		/// 
		/// TrailerField ::= INTEGER { trailerFieldBC(1) }
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

			if (!saltLength.Equals(DEFAULT_SALT_LENGTH))
			{
				v.add(new DERTaggedObject(true, 2, saltLength));
			}

			if (!trailerField.Equals(DEFAULT_TRAILER_FIELD))
			{
				v.add(new DERTaggedObject(true, 3, trailerField));
			}

			return new DERSequence(v);
		}
	}

}