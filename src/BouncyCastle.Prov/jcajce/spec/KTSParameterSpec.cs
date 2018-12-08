using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.x9;

namespace org.bouncycastle.jcajce.spec
{

	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Parameter spec for doing KTS based wrapping via the Cipher API.
	/// </summary>
	public class KTSParameterSpec : AlgorithmParameterSpec
	{
		private readonly string wrappingKeyAlgorithm;
		private readonly int keySizeInBits;
		private readonly AlgorithmParameterSpec parameterSpec;
		private readonly AlgorithmIdentifier kdfAlgorithm;
		private byte[] otherInfo;

		/// <summary>
		/// Builder class for creating a KTSParameterSpec.
		/// </summary>
		public sealed class Builder
		{
			internal readonly string algorithmName;
			internal readonly int keySizeInBits;

			internal AlgorithmParameterSpec parameterSpec;
			internal AlgorithmIdentifier kdfAlgorithm;
			internal byte[] otherInfo;

			/// <summary>
			/// Basic builder.
			/// </summary>
			/// <param name="algorithmName"> the algorithm name for the secret key we use for wrapping. </param>
			/// <param name="keySizeInBits"> the size of the wrapping key we want to produce in bits. </param>
			public Builder(string algorithmName, int keySizeInBits) : this(algorithmName, keySizeInBits, null)
			{
			}

			/// <summary>
			/// Basic builder.
			/// </summary>
			/// <param name="algorithmName"> the algorithm name for the secret key we use for wrapping. </param>
			/// <param name="keySizeInBits"> the size of the wrapping key we want to produce in bits. </param>
			/// <param name="otherInfo">     the otherInfo/IV encoding to be applied to the KDF. </param>
			public Builder(string algorithmName, int keySizeInBits, byte[] otherInfo)
			{
				this.algorithmName = algorithmName;
				this.keySizeInBits = keySizeInBits;
				this.kdfAlgorithm = new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_kdf_kdf3, new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha256));
				this.otherInfo = (otherInfo == null) ? new byte[0] : Arrays.clone(otherInfo);
			}

			/// <summary>
			/// Set the algorithm parameter spec to be used with the wrapper.
			/// </summary>
			/// <param name="parameterSpec"> the algorithm parameter spec to be used in wrapping/unwrapping. </param>
			/// <returns> the current Builder instance. </returns>
			public Builder withParameterSpec(AlgorithmParameterSpec parameterSpec)
			{
				this.parameterSpec = parameterSpec;

				return this;
			}

			/// <summary>
			/// Set the KDF algorithm and digest algorithm for wrap key generation.
			/// </summary>
			/// <param name="kdfAlgorithm"> the KDF algorithm to apply. </param>
			/// <returns> the current Builder instance. </returns>
			public Builder withKdfAlgorithm(AlgorithmIdentifier kdfAlgorithm)
			{
				this.kdfAlgorithm = kdfAlgorithm;

				return this;
			}

			/// <summary>
			/// Build the new parameter spec.
			/// </summary>
			/// <returns> a new parameter spec configured according to the builder state. </returns>
			public KTSParameterSpec build()
			{
				return new KTSParameterSpec(algorithmName, keySizeInBits, parameterSpec, kdfAlgorithm, otherInfo);
			}
		}

		private KTSParameterSpec(string wrappingKeyAlgorithm, int keySizeInBits, AlgorithmParameterSpec parameterSpec, AlgorithmIdentifier kdfAlgorithm, byte[] otherInfo)
		{
			this.wrappingKeyAlgorithm = wrappingKeyAlgorithm;
			this.keySizeInBits = keySizeInBits;
			this.parameterSpec = parameterSpec;
			this.kdfAlgorithm = kdfAlgorithm;
			this.otherInfo = otherInfo;
		}

		/// <summary>
		/// Return the name of the algorithm for the wrapping key this key spec should use.
		/// </summary>
		/// <returns> the key algorithm. </returns>
		public virtual string getKeyAlgorithmName()
		{
			return wrappingKeyAlgorithm;
		}

		/// <summary>
		/// Return the size of the key (in bits) for the wrapping key this key spec should use.
		/// </summary>
		/// <returns> length in bits of the key to be calculated. </returns>
		public virtual int getKeySize()
		{
			return keySizeInBits;
		}

		/// <summary>
		/// Return the algorithm parameter spec to be applied with the private key when the encapsulation is decrypted.
		/// </summary>
		/// <returns> the algorithm parameter spec to be used with the private key. </returns>
		public virtual AlgorithmParameterSpec getParameterSpec()
		{
			return parameterSpec;
		}

		/// <summary>
		/// Return the AlgorithmIdentifier for the KDF to do key derivation after extracting the secret.
		/// </summary>
		/// <returns> the AlgorithmIdentifier for the SecretKeyFactory's KDF. </returns>
		public virtual AlgorithmIdentifier getKdfAlgorithm()
		{
			return kdfAlgorithm;
		}

		/// <summary>
		/// Return the otherInfo data for initialising the KDF.
		/// </summary>
		/// <returns> the otherInfo data. </returns>
		public virtual byte[] getOtherInfo()
		{
			return Arrays.clone(otherInfo);
		}
	}

}