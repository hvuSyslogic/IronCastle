﻿using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.rosstandart;
using org.bouncycastle.asn1.gm;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.util
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using GMObjectIdentifiers = org.bouncycastle.asn1.gm.GMObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RosstandartObjectIdentifiers = org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Integers = org.bouncycastle.util.Integers;

	/// <summary>
	/// Configuration class for a PBKDF using PKCS#5 Scheme 2.
	/// </summary>
	public class PBKDF2Config : PBKDFConfig
	{
		/// <summary>
		/// AlgorithmIdentifier for a PRF using HMac with SHA-1
		/// </summary>
		public static readonly AlgorithmIdentifier PRF_SHA1 = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_hmacWithSHA1, DERNull.INSTANCE);

		/// <summary>
		/// AlgorithmIdentifier for a PRF using HMac with SHA-256
		/// </summary>
		public static readonly AlgorithmIdentifier PRF_SHA256 = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_hmacWithSHA256, DERNull.INSTANCE);

		/// <summary>
		/// AlgorithmIdentifier for a PRF using HMac with SHA-512
		/// </summary>
		public static readonly AlgorithmIdentifier PRF_SHA512 = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_hmacWithSHA512, DERNull.INSTANCE);

		/// <summary>
		/// AlgorithmIdentifier for a PRF using HMac with SHA3-256
		/// </summary>
		public static readonly AlgorithmIdentifier PRF_SHA3_256 = new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_256, DERNull.INSTANCE);

		/// <summary>
		/// AlgorithmIdentifier for a PRF using SHA3-512
		/// </summary>
		public static readonly AlgorithmIdentifier PRF_SHA3_512 = new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_512, DERNull.INSTANCE);

		private static readonly Map PRFS_SALT = new HashMap();

		static PBKDF2Config()
		{
			PRFS_SALT.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA1, Integers.valueOf(20));
			PRFS_SALT.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA256, Integers.valueOf(32));
			PRFS_SALT.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA512, Integers.valueOf(64));
			PRFS_SALT.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA224, Integers.valueOf(28));
			PRFS_SALT.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA384, Integers.valueOf(48));
			PRFS_SALT.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_224, Integers.valueOf(28));
			PRFS_SALT.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_256, Integers.valueOf(32));
			PRFS_SALT.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_384, Integers.valueOf(48));
			PRFS_SALT.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_512, Integers.valueOf(64));
			PRFS_SALT.put(CryptoProObjectIdentifiers_Fields.gostR3411Hmac, Integers.valueOf(32));
			PRFS_SALT.put(RosstandartObjectIdentifiers_Fields.id_tc26_hmac_gost_3411_12_256, Integers.valueOf(32));
			PRFS_SALT.put(RosstandartObjectIdentifiers_Fields.id_tc26_hmac_gost_3411_12_512, Integers.valueOf(64));
			PRFS_SALT.put(GMObjectIdentifiers_Fields.hmac_sm3, Integers.valueOf(32));
		}

		internal static int getSaltSize(ASN1ObjectIdentifier algorithm)
		{
			if (!PRFS_SALT.containsKey(algorithm))
			{
				throw new IllegalStateException("no salt size for algorithm: " + algorithm);
			}

			return ((int?)PRFS_SALT.get(algorithm)).Value;
		}

		public class Builder
		{
			internal int iterationCount = 1024;
			internal int saltLength = -1;
			internal AlgorithmIdentifier prf = PRF_SHA1;

			/// <summary>
			/// Base constructor.
			/// 
			/// This configures the builder to use an iteration count of 1024, and the HMacSHA1 PRF.
			/// </summary>
			public Builder()
			{
			}

			/// <summary>
			/// Set the iteration count for the PBE calculation.
			/// </summary>
			/// <param name="iterationCount"> the iteration count to apply to the key creation. </param>
			/// <returns> the current builder. </returns>
			public virtual Builder withIterationCount(int iterationCount)
			{
				this.iterationCount = iterationCount;

				return this;
			}

			/// <summary>
			/// Set the PRF to use for key generation. By default this is HmacSHA1.
			/// </summary>
			/// <param name="prf"> algorithm id for PRF. </param>
			/// <returns> the current builder. </returns>
			public virtual Builder withPRF(AlgorithmIdentifier prf)
			{
				this.prf = prf;

				return this;
			}

			/// <summary>
			/// Set the length of the salt to use.
			/// </summary>
			/// <param name="saltLength"> the length of the salt (in octets) to use. </param>
			/// <returns> the current builder. </returns>
			public virtual Builder withSaltLength(int saltLength)
			{
				this.saltLength = saltLength;

				return this;
			}

			public virtual PBKDF2Config build()
			{
				return new PBKDF2Config(this);
			}
		}

		private readonly int iterationCount;
		private readonly int saltLength;
		private readonly AlgorithmIdentifier prf;

		private PBKDF2Config(Builder builder) : base(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers_Fields.id_PBKDF2)
		{

			this.iterationCount = builder.iterationCount;
			this.prf = builder.prf;

			if (builder.saltLength < 0)
			{
				this.saltLength = getSaltSize(prf.getAlgorithm());
			}
			else
			{
				this.saltLength = builder.saltLength;
			}
		}

		public virtual int getIterationCount()
		{
			return iterationCount;
		}

		public virtual AlgorithmIdentifier getPRF()
		{
			return prf;
		}

		public virtual int getSaltLength()
		{
			return saltLength;
		}
	}

}