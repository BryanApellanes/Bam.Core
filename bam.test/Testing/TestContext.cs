/*
	Copyright © Bryan Apellanes 2015  
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Bam.Net.Testing
{
    /// <summary>
    /// The context specific to a single set of tests.  Tracks
    /// the SetupContext, the test delegate and the assertions
    /// made during the verification phase of the test.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class TestContext<T>
    {
        readonly SetupContext _setupContext;
        readonly Because _because;
        readonly Action<T> _testMethod;
        readonly Action<T, SetupContext> _altTestMethod;
        readonly Func<T, object> _outputAction;

        internal TestContext(SetupContext setupContext, string testDescription)
        {
            this._setupContext = setupContext;
            this._because = new Because(testDescription, setupContext);
            this._testMethod = (o) => { };
            this._altTestMethod = (o, c) => { };
            this._outputAction = (o) => o;
        }

        /// <summary>
        /// Creates a new test Context instance using the specified setupContext and 
        /// test description.
        /// </summary>
        /// <param name="setupContext">The setup or initialization context used for this
        /// test.</param>
        /// <param name="testDescription">The description of the current test.</param>
        /// <param name="testMethod">The delegate containing the test actions</param>
        public TestContext(SetupContext setupContext, string testDescription, Action<T> testMethod)
            : this(setupContext, testDescription)
        {
            this._testMethod = testMethod;
        }

        public TestContext(SetupContext setupContext, string testDescription, Action<T, SetupContext> altTestMethod)
            : this(setupContext, testDescription)
        {
            this._altTestMethod = altTestMethod;
        }

        /// <summary>
        /// Creates a new test Context instance using the specified setupContext and 
        /// test description.
        /// </summary>
        /// <param name="setupContext">The setup or initialization context used for this
        /// test.</param>
        /// <param name="testDescription">The description of the current test.</param>
        /// <param name="outputAction">The delegate containing the test which returns a value
        /// that can be validated during the verification phase of the test.</param>
        public TestContext(SetupContext setupContext, string testDescription, Func<T, object> outputAction)
            : this(setupContext, testDescription)
        {
            this._outputAction = outputAction;
        }

        /// <summary>
        /// Causes the test to run, same as It.
        /// </summary>
        public TestContext<T> TheTest => It;

        bool run;
        /// <summary>
        /// Causes the test to run, same as TheTest.
        /// </summary>
        public TestContext<T> It
        {
            get
            {
                if (!run)
                {
                    run = true;
                    try
                    {
                        T objectUnderTest = _setupContext.Get<T>();
                        _testMethod(objectUnderTest);
                        _altTestMethod(objectUnderTest, _setupContext);
                        _because.Result = _outputAction(objectUnderTest);
                        _setupContext.ObjectUnderTest = objectUnderTest;
                    }
                    catch (Exception ex)
                    {
                        _because.ExceptionWasThrown(ex);
                    }
                }
                return this;
            }
        }

        /// <summary>
        /// The entry point into test validation.  Calls the specified
        /// actionToAssertResults passing it the Because object of the 
        /// current test Context.
        /// </summary>
        /// <param name="actionToAssertResults"></param>
        /// <returns></returns>
        public TestContext<T> ShouldPass(Action<Because> actionToAssertResults)
        {
            actionToAssertResults(_because);
            return this;
        }

        /// <summary>
        /// The entry point into test validation.  Calls the specified 
        /// actionToAssertResults passing it the Because object of the
        /// current test context and the object under test.
        /// </summary>
        /// <param name="actionToAssertResults"></param>
        /// <returns></returns>
        public TestContext<T> ShouldPass(Action<Because, AssertionProvider<T>> actionToAssertResults)
        {
            try
            {
                actionToAssertResults(_because, new AssertionProvider<T>(_because, (T)_setupContext.ObjectUnderTest, "Object Under Test"));
            }
            catch (Exception ex)
            {
                _because.ExceptionWasThrown(ex);
            }
            return this;
        }
        
        public TestContext<T> ShouldPass<TResult>(Action<Because, AssertionProvider<T>, TResult> actionToAssertResults)
        {
            try
            {
                actionToAssertResults(_because, new AssertionProvider<T>(_because, (T)_setupContext.ObjectUnderTest, "Object Under Test"), _because.ResultAs<TResult>());
            }
            catch (Exception ex)
            {
                _because.ExceptionWasThrown(ex);
            }
            return this;
        }

        /// <summary>
        /// Calls Write() on the IBecauseWriter for the current test and
        /// marks the test complete.
        /// </summary>
        /// <returns></returns>
        public Because SoBeHappy()
        {
            return _because.TestIsDone;
        }

        /// <summary>
        /// Calls Write() on the IBecauseWriter for the current test and
        /// marks the test complete then runs the specified cleanup action.  
        /// Same as Cleanup.
        /// </summary>
        /// <param name="cleanup"></param>
        /// <returns></returns>
        public Because SoBeHappy(Action<SetupContext> cleanup)
        {
            return Cleanup(cleanup);
        }

        /// <summary>
        /// Calls Write() on the IBecauseWriter for the current test and
        /// marks the test complete then runs the specified cleanup action.  
        /// Same as SoBeHappy.
        /// </summary>
        /// <param name="cleanup"></param>
        /// <returns></returns>
        public Because Cleanup(Action<SetupContext> cleanup)
        {
            return _because.TestIsDone.CleanUp(cleanup);
        }
    }
}
