/*
	Copyright © Bryan Apellanes 2015  
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text;

namespace Bam.Net.Testing
{
    /// <summary>
    /// Provides a mechanism by which assertions are tracked for a test.
    /// </summary>
    public class Because
    {
        readonly SetupContext _setupContext;
        readonly List<Assertion> _assertions;
        internal Because(string testDescription, SetupContext setupContext)
        {
            this.TestDescription = testDescription;
            this._assertions = new List<Assertion>();
            this._setupContext = setupContext;
        }

        /// <summary>
        /// Gets the description of the current test being run
        /// </summary>
        public string TestDescription
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the SetupContext instance for the current test.
        /// </summary>
        public SetupContext SetupContext => this._setupContext;

        /// <summary>
        /// Gets the object under test from the underlying SetupContext.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public T ObjectUnderTest<T>()
        {
            return (T)this._setupContext.ObjectUnderTest;
        }

        /// <summary>
        /// Gets a value indicating whether the current test has passed.
        /// </summary>
        public bool Passed =>
            (from item in _assertions
                where item.Passed == false
                select item).FirstOrDefault() == null;

        /// <summary>
        /// Asserts that the specified value is true
        /// </summary>
        /// <param name="descriptionOfTrueAssertion">A description of the true value.  Read as:  ItsTrue "Michael Jordan is the best of all time"</param>
        /// <param name="shouldBeTrue"></param>
        /// <param name="failureMessage"></param>
        public void ItsTrue(string descriptionOfTrueAssertion, bool shouldBeTrue, string failureMessage = "")
        {
            _assertions.Add(
                new Assertion 
                { 
                    Passed = shouldBeTrue == true, 
                    SuccessMessage = descriptionOfTrueAssertion,
                    FailureMessage = failureMessage
                }); 
        }

        public void ItsTrue(string descriptionOfTrueAssertion, Action doesntThrow, string failureMessage = "")
        {
            _assertions.Add(
                new Assertion
                {
                    Passed = doesntThrow.Try(),
                    SuccessMessage = descriptionOfTrueAssertion,
                    FailureMessage = failureMessage
                });
        }
                
        /// <summary>
        /// Asserts that the specified value is false
        /// </summary>
        /// <param name="descriptionOfFalseAssertion">A description of the false value.  Read as: ItsFalse "John Stockton was the number one point guard of all time (Magic Johnson was, John Stockton was second)" </param>
        /// <param name="shouldBeFalse">A value that should evaluate to false.</param>
        /// <param name="failureMessage">The message to display if the `shouldBeFalse` value is actually `true`.</param>
        public void ItsFalse(string descriptionOfFalseAssertion, bool shouldBeFalse, string failureMessage = "")
        {
            _assertions.Add(
                new Assertion 
                { 
                    Passed = shouldBeFalse == false, 
                    SuccessMessage = descriptionOfFalseAssertion,
                    FailureMessage = failureMessage
                });
        }
        
        /// <summary>
        /// Asserts that the type of the result of the test Function 
        /// is the same as the type specified by generic type T.  Only valid
        /// if the test method returned a value.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        public void ResultIs<T>()
        {
            Type type = typeof(T);
            _assertions.Add(
                new Assertion
                {
                    Passed = Result != null && Result.GetType() == typeof(T),
                    SuccessMessage = $"result is of type {type.Name}",
                    FailureMessage = $"result is NOT of type {type.Name}"
                });
        }

        /// <summary>
        /// Asserts that the result of the test function
        /// is equal to the specified object using the .Equals 
        /// method.
        /// </summary>
        /// <param name="obj"></param>
        public void ResultEquals(object obj)
        {
            _assertions.Add(
                new Assertion
                {
                    Passed = Result.Equals(obj),
                    SuccessMessage = $"result equals the specified value ({obj.ToString()})",
                    FailureMessage = $"result does NOT equal the specified value ({obj.ToString()})"
                });
        }

        /// <summary>
        /// Asserts that the result of the test function
        /// is the same as the specified object using
        /// the equality comparison operator ==
        /// </summary>
        /// <param name="obj"></param>
        public void ResultIsSameAs(object obj)
        {
            _assertions.Add(
                new Assertion
                {
                    Passed = Result == obj,
                    SuccessMessage = $"result is same as the specified value ({obj.ToString()})",
                    FailureMessage = $"result is NOT same as the specified value ({obj.ToString()})"
                });
        }

        /// <summary>
        /// Does not perform an assertion, rather outputs the string representation of the specified obj
        /// using ToString().
        /// </summary>
        /// <param name="obj"></param>
        public void IllLookAtIt(object obj)
        {
            _assertions.Add(
                new Assertion
                {
                    Passed = true,
                    SuccessMessage = $"I'll inspect the value ({obj.ToString()})"
                });
        }

        /// <summary>
        /// Does not perform an assertion, rather outputs the properties of the
        /// result of the test function
        /// </summary>
        /// <typeparam name="T"></typeparam>
        public void IllLookAtTheResultsProperties<T>()
        {
            IllLookAtItsProperties<T>((T)Result);
        }

        /// <summary>
        /// Does not perform an assertion, rather outputs the properties of the specified obj.
        /// </summary>
        /// <param name="obj"></param>
        public void IllLookAtItsProperties<T>(T obj)
        {
            _assertions.Add(
                new Assertion
                {
                    Passed = true,
                    SuccessMessage = $"I'll inspect the properties:\r\n{obj.PropertiesToString()}"
                });
        }
        
        /// <summary>
        /// Asserts that the result inherits from (derives from/is a subclass of) the specified
        /// generic type T.  Only valid if the test method returned a value.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        public void ResultDerivesFrom<T>()
        {
            Type type = typeof(T);
            _assertions.Add(
                new Assertion
                {
                    Passed = Result.GetType().IsSubclassOf(type),
                    SuccessMessage = $"result is a subclass of type {type.Name}",
                    FailureMessage = $"result is NOT of type {type.Name}"
                });
        }

        internal void ExceptionWasThrown(Exception ex)
        {
            _assertions.Add(new Assertion
            {
                Passed = false,
                FailureMessage =
                    $"an exception was thrown ({ex.Message}):\r\n{ex.StackTrace}"
            }); 
        }

        internal Assertion[] Assertions => this._assertions.ToArray();
        
        public T ResultAs<T>()
        {
            return (T)Result;
        }

        /// <summary>
        /// The return value of the test method execution
        /// </summary>        
        public object Result { get; set; }

        bool _testIsDone;
        internal Because TestIsDone
        {
            get
            {
                if (!_testIsDone)
                {
                    _testIsDone = true;
                    _setupContext.Get<IBecauseWriter>().Write(this);                    
                }
                return this;
            }
        }

        internal Because CleanUp(Action<SetupContext> cleanup)
        {
            cleanup(_setupContext);
            return this;
        }

        /// <summary>
        /// Throws an exception if the test failed.  Same as ThrowExceptionIfTheTestFailed. 
        /// </summary>
        /// <param name="message"></param>
        public void OrNot(string message = "The test failed, please see test output for more information.")
        {
            ThrowExceptionIfTheTestFailed(message);
        }

        /// <summary>
        /// Throws an exception if the test failed.  Same as OrNot.
        /// </summary>
        /// <param name="message"></param>
        public void ThrowExceptionIfTheTestFailed(string message = "The test failed, please see test output for more information.")
        {
            if (!Passed)
            {
                throw new Exception(message);
            }
        }

        /// <summary>
        /// Throws an exception if the test failed.  Same as ThrowExceptionIfTheTestFailed.
        /// </summary>
        public void UnlessItFailed(string message = "The test failed, please see test output for more information.")
        {
            ThrowExceptionIfTheTestFailed(message);
        }
    }
}
