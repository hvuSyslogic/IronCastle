using System.IO;
using BouncyCastle.Core.Port.java.io;
using BouncyCastle.Core.Port.java.text;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.@params
{

	using SkeinDigest = org.bouncycastle.crypto.digests.SkeinDigest;
	using SkeinEngine = org.bouncycastle.crypto.digests.SkeinEngine;
	using SkeinMac = org.bouncycastle.crypto.macs.SkeinMac;
	using Integers = org.bouncycastle.util.Integers;

	/// <summary>
	/// Parameters for the Skein hash function - a series of byte[] strings identified by integer tags.
	/// <para>
	/// Parameterised Skein can be used for:
	/// <ul>
	/// <li>MAC generation, by providing a <seealso cref="SkeinParameters.Builder#setKey(byte[]) key"/>.</li>
	/// <li>Randomised hashing, by providing a <seealso cref="SkeinParameters.Builder#setNonce(byte[]) nonce"/>.</li>
	/// <li>A hash function for digital signatures, associating a
	/// <seealso cref="SkeinParameters.Builder#setPublicKey(byte[]) public key"/> with the message digest.</li>
	/// <li>A key derivation function, by providing a
	/// <seealso cref="SkeinParameters.Builder#setKeyIdentifier(byte[]) key identifier"/>.</li>
	/// <li>Personalised hashing, by providing a
	/// <seealso cref="SkeinParameters.Builder#setPersonalisation(Date, String, String) recommended format"/> or
	/// <seealso cref="SkeinParameters.Builder#setPersonalisation(byte[]) arbitrary"/> personalisation string.</li>
	/// </ul>
	/// 
	/// </para>
	/// </summary>
	/// <seealso cref= SkeinEngine </seealso>
	/// <seealso cref= SkeinDigest </seealso>
	/// <seealso cref= SkeinMac </seealso>
	public class SkeinParameters : CipherParameters
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

		private Hashtable parameters;

		public SkeinParameters() : this(new Hashtable())
		{
		}


		private SkeinParameters(Hashtable parameters)
		{
			this.parameters = parameters;
		}

		/// <summary>
		/// Obtains a map of type (Integer) to value (byte[]) for the parameters tracked in this object.
		/// </summary>
		public virtual Hashtable getParameters()
		{
			return parameters;
		}

		/// <summary>
		/// Obtains the value of the <seealso cref="#PARAM_TYPE_KEY key parameter"/>, or <code>null</code> if not
		/// set.
		/// </summary>
		public virtual byte[] getKey()
		{
			return (byte[])parameters.get(Integers.valueOf(PARAM_TYPE_KEY));
		}

		/// <summary>
		/// Obtains the value of the <seealso cref="#PARAM_TYPE_PERSONALISATION personalisation parameter"/>, or
		/// <code>null</code> if not set.
		/// </summary>
		public virtual byte[] getPersonalisation()
		{
			return (byte[])parameters.get(Integers.valueOf(PARAM_TYPE_PERSONALISATION));
		}

		/// <summary>
		/// Obtains the value of the <seealso cref="#PARAM_TYPE_PUBLIC_KEY public key parameter"/>, or
		/// <code>null</code> if not set.
		/// </summary>
		public virtual byte[] getPublicKey()
		{
			return (byte[])parameters.get(Integers.valueOf(PARAM_TYPE_PUBLIC_KEY));
		}

		/// <summary>
		/// Obtains the value of the <seealso cref="#PARAM_TYPE_KEY_IDENTIFIER key identifier parameter"/>, or
		/// <code>null</code> if not set.
		/// </summary>
		public virtual byte[] getKeyIdentifier()
		{
			return (byte[])parameters.get(Integers.valueOf(PARAM_TYPE_KEY_IDENTIFIER));
		}

		/// <summary>
		/// Obtains the value of the <seealso cref="#PARAM_TYPE_NONCE nonce parameter"/>, or <code>null</code> if
		/// not set.
		/// </summary>
		public virtual byte[] getNonce()
		{
			return (byte[])parameters.get(Integers.valueOf(PARAM_TYPE_NONCE));
		}

		/// <summary>
		/// A builder for <seealso cref="SkeinParameters"/>.
		/// </summary>
		public class Builder
		{
			internal Hashtable parameters = new Hashtable();

			public Builder()
			{
			}

			public Builder(Hashtable paramsMap)
			{
				Enumeration keys = paramsMap.keys();
				while (keys.hasMoreElements())
				{
					int? key = (int?)keys.nextElement();
					parameters.put(key, paramsMap.get(key));
				}
			}

			public Builder(SkeinParameters @params)
			{
				Enumeration keys = @params.parameters.keys();
				while (keys.hasMoreElements())
				{
					int? key = (int?)keys.nextElement();
					parameters.put(key, @params.parameters.get(key));
				}
			}

			/// <summary>
			/// Sets a parameters to apply to the Skein hash function.<br>
			/// Parameter types must be in the range 0,5..62, and cannot use the value {@link
			/// #PARAM_TYPE_MESSAGE} (reserved for message body).
			/// <para>
			/// Parameters with type &lt; <seealso cref="#PARAM_TYPE_MESSAGE"/> are processed before
			/// the message content, parameters with type &gt; <seealso cref="#PARAM_TYPE_MESSAGE"/>
			/// are processed after the message and prior to output.
			/// 
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
				if ((type != PARAM_TYPE_KEY) && (type < PARAM_TYPE_CONFIG || type >= PARAM_TYPE_OUTPUT || type == PARAM_TYPE_MESSAGE))
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
			/// Sets the <seealso cref="#PARAM_TYPE_KEY"/> parameter.
			/// </summary>
			public virtual Builder setKey(byte[] key)
			{
				return set(PARAM_TYPE_KEY, key);
			}

			/// <summary>
			/// Sets the <seealso cref="#PARAM_TYPE_PERSONALISATION"/> parameter.
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
			/// 
			/// </para>
			/// </summary>
			/// <param name="date">          the date the personalised application of the Skein was defined. </param>
			/// <param name="emailAddress">  the email address of the creation of the personalised application. </param>
			/// <param name="distinguisher"> an arbitrary personalisation string distinguishing the application. </param>
			/// <returns> the current builder. </returns>
			public virtual Builder setPersonalisation(DateTime date, string emailAddress, string distinguisher)
			{
				try
				{
					ByteArrayOutputStream bout = new ByteArrayOutputStream();
					OutputStreamWriter @out = new OutputStreamWriter(bout, "UTF-8");
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
			/// <returns> the current builder. </returns>
			 public virtual Builder setPersonalisation(DateTime date, Locale dateLocale, string emailAddress, string distinguisher)
			 {
				 try
				 {

					 ByteArrayOutputStream bout = new ByteArrayOutputStream();

					 OutputStreamWriter @out = new OutputStreamWriter(bout, "UTF-8");

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
			/// Sets the <seealso cref="SkeinParameters#PARAM_TYPE_KEY_IDENTIFIER"/> parameter.
			/// </summary>
			public virtual Builder setPublicKey(byte[] publicKey)
			{
				return set(PARAM_TYPE_PUBLIC_KEY, publicKey);
			}

			/// <summary>
			/// Sets the <seealso cref="SkeinParameters#PARAM_TYPE_KEY_IDENTIFIER"/> parameter.
			/// </summary>
			public virtual Builder setKeyIdentifier(byte[] keyIdentifier)
			{
				return set(PARAM_TYPE_KEY_IDENTIFIER, keyIdentifier);
			}

			/// <summary>
			/// Sets the <seealso cref="SkeinParameters#PARAM_TYPE_NONCE"/> parameter.
			/// </summary>
			public virtual Builder setNonce(byte[] nonce)
			{
				return set(PARAM_TYPE_NONCE, nonce);
			}

			/// <summary>
			/// Constructs a new <seealso cref="SkeinParameters"/> instance with the parameters provided to this
			/// builder.
			/// </summary>
			public virtual SkeinParameters build()
			{
				return new SkeinParameters(parameters);
			}
		}
	}

}