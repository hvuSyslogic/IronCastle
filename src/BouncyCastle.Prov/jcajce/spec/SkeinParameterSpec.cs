using System;

namespace org.bouncycastle.jcajce.spec
{

	using Arrays = org.bouncycastle.util.Arrays;
	using Integers = org.bouncycastle.util.Integers;

	/// <summary>
	/// Parameters for the Skein hash function - a series of byte[] strings identified by integer tags.
	/// <para>
	/// Parameterised Skein can be used for:
	/// <ul>
	/// <li>MAC generation, by providing a <seealso cref="org.bouncycastle.jcajce.spec.SkeinParameterSpec.Builder#setKey(byte[]) key"/>.</li>
	/// <li>Randomised hashing, by providing a <seealso cref="org.bouncycastle.jcajce.spec.SkeinParameterSpec.Builder#setNonce(byte[]) nonce"/>.</li>
	/// <li>A hash function for digital signatures, associating a
	/// <seealso cref="org.bouncycastle.jcajce.spec.SkeinParameterSpec.Builder#setPublicKey(byte[]) public key"/> with the message digest.</li>
	/// <li>A key derivation function, by providing a
	/// <seealso cref="org.bouncycastle.jcajce.spec.SkeinParameterSpec.Builder#setKeyIdentifier(byte[]) key identifier"/>.</li>
	/// <li>Personalised hashing, by providing a
	/// <seealso cref="org.bouncycastle.jcajce.spec.SkeinParameterSpec.Builder#setPersonalisation(java.util.Date, String, String) recommended format"/> or
	/// <seealso cref="org.bouncycastle.jcajce.spec.SkeinParameterSpec.Builder#setPersonalisation(byte[]) arbitrary"/> personalisation string.</li>
	/// </ul>
	/// 
	/// </para>
	/// </summary>
	/// <seealso cref= org.bouncycastle.crypto.digests.SkeinEngine </seealso>
	/// <seealso cref= org.bouncycastle.crypto.digests.SkeinDigest </seealso>
	/// <seealso cref= org.bouncycastle.crypto.macs.SkeinMac </seealso>
	public class SkeinParameterSpec : AlgorithmParameterSpec
	{
		/// <summary>
		/// The parameter type for a secret key, supporting MAC or KDF functions: {@value
		/// #PARAM_TYPE_KEY}.
		/// </summary>
		public const int PARAM_TYPE_KEY = 0;

		/// <summary>
		/// The parameter type for the Skein configuration block: {@value #PARAM_TYPE_CONFIG}.
		/// </summary>
		public const int PARAM_TYPE_CONFIG = 4;

		/// <summary>
		/// The parameter type for a personalisation string: {@value #PARAM_TYPE_PERSONALISATION}.
		/// </summary>
		public const int PARAM_TYPE_PERSONALISATION = 8;

		/// <summary>
		/// The parameter type for a public key: {@value #PARAM_TYPE_PUBLIC_KEY}.
		/// </summary>
		public const int PARAM_TYPE_PUBLIC_KEY = 12;

		/// <summary>
		/// The parameter type for a key identifier string: {@value #PARAM_TYPE_KEY_IDENTIFIER}.
		/// </summary>
		public const int PARAM_TYPE_KEY_IDENTIFIER = 16;

		/// <summary>
		/// The parameter type for a nonce: {@value #PARAM_TYPE_NONCE}.
		/// </summary>
		public const int PARAM_TYPE_NONCE = 20;

		/// <summary>
		/// The parameter type for the message: {@value #PARAM_TYPE_MESSAGE}.
		/// </summary>
		public const int PARAM_TYPE_MESSAGE = 48;

		/// <summary>
		/// The parameter type for the output transformation: {@value #PARAM_TYPE_OUTPUT}.
		/// </summary>
		public const int PARAM_TYPE_OUTPUT = 63;

		private Map parameters;

		public SkeinParameterSpec() : this(new HashMap())
		{
		}

		private SkeinParameterSpec(Map parameters)
		{
			this.parameters = Collections.unmodifiableMap(parameters);
		}

		/// <summary>
		/// Obtains a map of type (Integer) to value (byte[]) for the parameters tracked in this object.
		/// </summary>
		public virtual Map getParameters()
		{
			return parameters;
		}

		/// <summary>
		/// Obtains the value of the <seealso cref="#PARAM_TYPE_KEY key parameter"/>, or <code>null</code> if not
		/// set.
		/// </summary>
		public virtual byte[] getKey()
		{
			return Arrays.clone((byte[])parameters.get(Integers.valueOf(PARAM_TYPE_KEY)));
		}

		/// <summary>
		/// Obtains the value of the <seealso cref="#PARAM_TYPE_PERSONALISATION personalisation parameter"/>, or
		/// <code>null</code> if not set.
		/// </summary>
		public virtual byte[] getPersonalisation()
		{
			return Arrays.clone((byte[])parameters.get(Integers.valueOf(PARAM_TYPE_PERSONALISATION)));
		}

		/// <summary>
		/// Obtains the value of the <seealso cref="#PARAM_TYPE_PUBLIC_KEY public key parameter"/>, or
		/// <code>null</code> if not set.
		/// </summary>
		public virtual byte[] getPublicKey()
		{
			return Arrays.clone((byte[])parameters.get(Integers.valueOf(PARAM_TYPE_PUBLIC_KEY)));
		}

		/// <summary>
		/// Obtains the value of the <seealso cref="#PARAM_TYPE_KEY_IDENTIFIER key identifier parameter"/>, or
		/// <code>null</code> if not set.
		/// </summary>
		public virtual byte[] getKeyIdentifier()
		{
			return Arrays.clone((byte[])parameters.get(Integers.valueOf(PARAM_TYPE_KEY_IDENTIFIER)));
		}

		/// <summary>
		/// Obtains the value of the <seealso cref="#PARAM_TYPE_NONCE nonce parameter"/>, or <code>null</code> if
		/// not set.
		/// </summary>
		public virtual byte[] getNonce()
		{
			return Arrays.clone((byte[])parameters.get(Integers.valueOf(PARAM_TYPE_NONCE)));
		}

		/// <summary>
		/// A builder for <seealso cref="org.bouncycastle.jcajce.spec.SkeinParameterSpec"/>.
		/// </summary>
		public class Builder
		{
			internal Map parameters = new HashMap();

			public Builder()
			{
			}

			public Builder(SkeinParameterSpec @params)
			{
				Iterator keys = @params.parameters.keySet().iterator();
				while (keys.hasNext())
				{
					int? key = (int?)keys.next();
					parameters.put(key, @params.parameters.get(key));
				}
			}

			/// <summary>
			/// Sets a parameters to apply to the Skein hash function.<br>
			/// Parameter types must be in the range 0,5..62, and cannot use the value {@value
			/// org.bouncycastle.jcajce.spec.SkeinParameterSpec#PARAM_TYPE_MESSAGE} (reserved for message body).
			/// <para>
			/// Parameters with type &lt; {@value org.bouncycastle.jcajce.spec.SkeinParameterSpec#PARAM_TYPE_MESSAGE} are processed before
			/// the message content, parameters with type &gt; {@value org.bouncycastle.jcajce.spec.SkeinParameterSpec#PARAM_TYPE_MESSAGE}
			/// are processed after the message and prior to output.
			/// </para>
			/// </summary>
			/// <param name="type">  the type of the parameter, in the range 5..62. </param>
			/// <param name="value"> the byte sequence of the parameter. </param>
			/// <returns> the current builder instance. </returns>
			public virtual Builder set(int type, byte[] value)
			{
				if (value == null)
				{
					throw new IllegalArgumentException("Parameter value must not be null.");
				}
				if ((type != PARAM_TYPE_KEY) && (type <= PARAM_TYPE_CONFIG || type >= PARAM_TYPE_OUTPUT || type == PARAM_TYPE_MESSAGE))
				{
					throw new IllegalArgumentException("Parameter types must be in the range 0,5..47,49..62.");
				}
				if (type == PARAM_TYPE_CONFIG)
				{
					throw new IllegalArgumentException("Parameter type " + PARAM_TYPE_CONFIG + " is reserved for internal use.");
				}
				this.parameters.put(Integers.valueOf(type), value);
				return this;
			}

			/// <summary>
			/// Sets the <seealso cref="org.bouncycastle.jcajce.spec.SkeinParameterSpec#PARAM_TYPE_KEY"/> parameter.
			/// </summary>
			public virtual Builder setKey(byte[] key)
			{
				return set(PARAM_TYPE_KEY, key);
			}

			/// <summary>
			/// Sets the <seealso cref="org.bouncycastle.jcajce.spec.SkeinParameterSpec#PARAM_TYPE_PERSONALISATION"/> parameter.
			/// </summary>
			public virtual Builder setPersonalisation(byte[] personalisation)
			{
				return set(PARAM_TYPE_PERSONALISATION, personalisation);
			}

			/// <summary>
			/// Implements the recommended personalisation format for Skein defined in Section 4.11 of
			/// the Skein 1.3 specification.
			/// <para>
			/// The format is <code>YYYYMMDD email@address distinguisher</code>, encoded to a byte
			/// sequence using UTF-8 encoding.
			/// </para>
			/// </summary>
			/// <param name="date">          the date the personalised application of the Skein was defined. </param>
			/// <param name="emailAddress">  the email address of the creation of the personalised application. </param>
			/// <param name="distinguisher"> an arbitrary personalisation string distinguishing the application. </param>
			/// <returns> the current builder instance. </returns>
			public virtual Builder setPersonalisation(DateTime date, string emailAddress, string distinguisher)
			{
				try
				{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.io.ByteArrayOutputStream bout = new java.io.ByteArrayOutputStream();
					ByteArrayOutputStream bout = new ByteArrayOutputStream();
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.io.OutputStreamWriter out = new java.io.OutputStreamWriter(bout, "UTF-8");
					OutputStreamWriter @out = new OutputStreamWriter(bout, "UTF-8");
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.text.DateFormat format = new java.text.SimpleDateFormat("YYYYMMDD");
					DateFormat format = new SimpleDateFormat("YYYYMMDD");
					@out.write(format.format(date));
					@out.write(" ");
					@out.write(emailAddress);
					@out.write(" ");
					@out.write(distinguisher);
					@out.close();
					return set(PARAM_TYPE_PERSONALISATION, bout.toByteArray());
				}
				catch (IOException e)
				{
					throw new IllegalStateException("Byte I/O failed: " + e);
				}
			}

			/// <summary>
			/// Implements the recommended personalisation format for Skein defined in Section 4.11 of
			/// the Skein 1.3 specification. You may need to use this method if the default locale
			/// doesn't use a Gregorian calender so that the GeneralizedTime produced is compatible implementations.
			/// <para>
			/// The format is <code>YYYYMMDD email@address distinguisher</code>, encoded to a byte
			/// sequence using UTF-8 encoding.
			/// 
			/// </para>
			/// </summary>
			/// <param name="date">          the date the personalised application of the Skein was defined. </param>
			/// <param name="dateLocale">    locale to be used for date interpretation. </param>
			/// <param name="emailAddress">  the email address of the creation of the personalised application. </param>
			/// <param name="distinguisher"> an arbitrary personalisation string distinguishing the application. </param>
			/// <returns> the current builder instance. </returns>
			public virtual Builder setPersonalisation(DateTime date, Locale dateLocale, string emailAddress, string distinguisher)
			{
				try
				{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.io.ByteArrayOutputStream bout = new java.io.ByteArrayOutputStream();
					ByteArrayOutputStream bout = new ByteArrayOutputStream();
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.io.OutputStreamWriter out = new java.io.OutputStreamWriter(bout, "UTF-8");
					OutputStreamWriter @out = new OutputStreamWriter(bout, "UTF-8");
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.text.DateFormat format = new java.text.SimpleDateFormat("YYYYMMDD", dateLocale);
					DateFormat format = new SimpleDateFormat("YYYYMMDD", dateLocale);
					@out.write(format.format(date));
					@out.write(" ");
					@out.write(emailAddress);
					@out.write(" ");
					@out.write(distinguisher);
					@out.close();
					return set(PARAM_TYPE_PERSONALISATION, bout.toByteArray());
				}
				catch (IOException e)
				{
					throw new IllegalStateException("Byte I/O failed: " + e);
				}
			}

			/// <summary>
			/// Sets the <seealso cref="org.bouncycastle.jcajce.spec.SkeinParameterSpec#PARAM_TYPE_KEY_IDENTIFIER"/> parameter.
			/// </summary>
			/// <returns> the current builder instance. </returns>
			public virtual Builder setPublicKey(byte[] publicKey)
			{
				return set(PARAM_TYPE_PUBLIC_KEY, publicKey);
			}

			/// <summary>
			/// Sets the <seealso cref="org.bouncycastle.jcajce.spec.SkeinParameterSpec#PARAM_TYPE_KEY_IDENTIFIER"/> parameter.
			/// </summary>
			/// <returns> the current builder instance. </returns>
			public virtual Builder setKeyIdentifier(byte[] keyIdentifier)
			{
				return set(PARAM_TYPE_KEY_IDENTIFIER, keyIdentifier);
			}

			/// <summary>
			/// Sets the <seealso cref="org.bouncycastle.jcajce.spec.SkeinParameterSpec#PARAM_TYPE_NONCE"/> parameter.
			/// </summary>
			/// <returns> the current builder instance. </returns>
			public virtual Builder setNonce(byte[] nonce)
			{
				return set(PARAM_TYPE_NONCE, nonce);
			}

			/// <summary>
			/// Constructs a new <seealso cref="org.bouncycastle.jcajce.spec.SkeinParameterSpec"/> instance with the parameters provided to this
			/// builder.
			/// </summary>
			public virtual SkeinParameterSpec build()
			{
				return new SkeinParameterSpec(parameters);
			}
		}
	}

}