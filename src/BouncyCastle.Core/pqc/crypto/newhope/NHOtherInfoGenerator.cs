using System.IO;
using BouncyCastle.Core.Port;
using org.bouncycastle.pqc.asn1;
using org.bouncycastle.Port;

namespace org.bouncycastle.pqc.crypto.newhope
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using KeyGenerationParameters = org.bouncycastle.crypto.KeyGenerationParameters;
	using DEROtherInfo = org.bouncycastle.crypto.util.DEROtherInfo;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;

	/// <summary>
	/// OtherInfo Generator for which can be used for populating the SuppPrivInfo field used to provide shared
	/// secret data used with NIST SP 800-56A agreement algorithms.
	/// </summary>
	public class NHOtherInfoGenerator
	{
		protected internal readonly DEROtherInfo.Builder otherInfoBuilder;
		protected internal readonly SecureRandom random;

		protected internal bool used = false;

		/// <summary>
		/// Create a basic builder with just the compulsory fields.
		/// </summary>
		/// <param name="algorithmID"> the algorithm associated with this invocation of the KDF. </param>
		/// <param name="partyUInfo">  sender party info. </param>
		/// <param name="partyVInfo">  receiver party info. </param>
		/// <param name="random"> a source of randomness. </param>
		public NHOtherInfoGenerator(AlgorithmIdentifier algorithmID, byte[] partyUInfo, byte[] partyVInfo, SecureRandom random)
		{
			this.otherInfoBuilder = new DEROtherInfo.Builder(algorithmID, partyUInfo, partyVInfo);
			this.random = random;
		}

		/// <summary>
		/// Party U (initiator) generation.
		/// </summary>
		public class PartyU : NHOtherInfoGenerator
		{
			internal AsymmetricCipherKeyPair aKp;
			internal NHAgreement agreement = new NHAgreement();

			public PartyU(AlgorithmIdentifier algorithmID, byte[] partyUInfo, byte[] partyVInfo, SecureRandom random) : base(algorithmID, partyUInfo, partyVInfo, random)
			{

				NHKeyPairGenerator kpGen = new NHKeyPairGenerator();

				kpGen.init(new KeyGenerationParameters(random, 2048));

				aKp = kpGen.generateKeyPair();

				agreement.init(aKp.getPrivate());
			}

			/// <summary>
			/// Add optional supplementary public info (DER tagged, implicit, 0).
			/// </summary>
			/// <param name="suppPubInfo"> supplementary public info. </param>
			/// <returns> the current builder instance. </returns>
			public virtual NHOtherInfoGenerator withSuppPubInfo(byte[] suppPubInfo)
			{
				this.otherInfoBuilder.withSuppPubInfo(suppPubInfo);

				return this;
			}

			public virtual byte[] getSuppPrivInfoPartA()
			{
				return getEncoded((NHPublicKeyParameters)aKp.getPublic());
			}

			public virtual DEROtherInfo generate(byte[] suppPrivInfoPartB)
			{
				if (used)
				{
					throw new IllegalStateException("builder already used");
				}

				used = true;

				this.otherInfoBuilder.withSuppPrivInfo(agreement.calculateAgreement(NHOtherInfoGenerator.getPublicKey(suppPrivInfoPartB)));

				return otherInfoBuilder.build();
			}
		}

		/// <summary>
		/// Party V (responder) generation.
		/// </summary>
		public class PartyV : NHOtherInfoGenerator
		{
			public PartyV(AlgorithmIdentifier algorithmID, byte[] partyUInfo, byte[] partyVInfo, SecureRandom random) : base(algorithmID, partyUInfo, partyVInfo, random)
			{
			}

			/// <summary>
			/// Add optional supplementary public info (DER tagged, implicit, 0).
			/// </summary>
			/// <param name="suppPubInfo"> supplementary public info. </param>
			/// <returns> the current builder instance. </returns>
			public virtual NHOtherInfoGenerator withSuppPubInfo(byte[] suppPubInfo)
			{
				this.otherInfoBuilder.withSuppPubInfo(suppPubInfo);

				return this;
			}

			public virtual byte[] getSuppPrivInfoPartB(byte[] suppPrivInfoPartA)
			{
				NHExchangePairGenerator exchGen = new NHExchangePairGenerator(random);

				ExchangePair bEp = exchGen.generateExchange(getPublicKey(suppPrivInfoPartA));

				this.otherInfoBuilder.withSuppPrivInfo(bEp.getSharedValue());

				return getEncoded((NHPublicKeyParameters)bEp.getPublicKey());
			}

			public virtual DEROtherInfo generate()
			{
				if (used)
				{
					throw new IllegalStateException("builder already used");
				}

				used = true;

				return otherInfoBuilder.build();
			}
		}

		private static byte[] getEncoded(NHPublicKeyParameters pubKey)
		{
			SubjectPublicKeyInfo pki;
			try
			{
				AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers_Fields.newHope);
				pki = new SubjectPublicKeyInfo(algorithmIdentifier, pubKey.getPubData());

				return pki.getEncoded();
			}
			catch (IOException)
			{
				return null;
			}
		}

		private static NHPublicKeyParameters getPublicKey(byte[] enc)
		{
			SubjectPublicKeyInfo pki = SubjectPublicKeyInfo.getInstance(enc);

			return new NHPublicKeyParameters(pki.getPublicKeyData().getOctets());
		}
	}

}