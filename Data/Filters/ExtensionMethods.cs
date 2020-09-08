using Advanced.Security.V3.Logging;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Data.Filters
{
    public static class ExtensionMethods
    {
        public static bool AllInUserContext<TSource>(this IQueryable<TSource> source, HttpContext context, Expression<Func<TSource, bool>> predicate) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);
            return source.Where(userPredicate).All(predicate);
        }

        public static bool AnyInUserContext<TSource>(this IQueryable<TSource> source, HttpContext context) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);
            return source.Any(userPredicate);
        }

        public static bool AnyInUserContext<TSource>(this IQueryable<TSource> source, HttpContext context, Expression<Func<TSource, bool>> predicate) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);
            return source.Where(userPredicate).Any(predicate);
        }

        public static int CountInUserContext<TSource>(this IQueryable<TSource> source, HttpContext context) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);
            return source.Count(userPredicate);
        }

        public static int CountInUserContext<TSource>(this IQueryable<TSource> source, HttpContext context, Expression<Func<TSource, bool>> predicate) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);
            return source.Where(userPredicate).Count(predicate);
        }

        public static TSource FirstInUserContext<TSource>(this IQueryable<TSource> source, HttpContext context) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);
            return source.First(userPredicate);
        }

        public static TSource FirstInUserContext<TSource>(this IQueryable<TSource> source, HttpContext context, Expression<Func<TSource, bool>> predicate) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);
            return source.Where(userPredicate).First(predicate);
        }

        public static TSource FirstOrDefaultInUserContext<TSource>(this IQueryable<TSource> source, HttpContext context) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);
            return source.FirstOrDefault(userPredicate);
        }

        public static TSource FirstOrDefaultInUserContext<TSource>(this IQueryable<TSource> source, HttpContext context, Expression<Func<TSource, bool>> predicate) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);
            return source.Where(userPredicate).FirstOrDefault(predicate);
        }

        public static TSource LastInUserContext<TSource>(this IQueryable<TSource> source, HttpContext context) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);
            return source.Last(userPredicate);
        }

        public static TSource LastInUserContext<TSource>(this IQueryable<TSource> source, HttpContext context, Expression<Func<TSource, bool>> predicate) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);
            return source.Where(userPredicate).Last(predicate);
        }

        public static TSource LastOrDefaultInUserContext<TSource>(this IQueryable<TSource> source, HttpContext context) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);
            return source.LastOrDefault(userPredicate);
        }

        public static TSource LastOrDefaultInUserContext<TSource>(this IQueryable<TSource> source, HttpContext context, Expression<Func<TSource, bool>> predicate) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);
            return source.Where(userPredicate).LastOrDefault(predicate);
        }

        public static long LongCountInUserContext<TSource>(this IQueryable<TSource> source, HttpContext context) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);
            return source.LongCount(userPredicate);
        }

        public static long LongCountInUserContext<TSource>(this IQueryable<TSource> source, HttpContext context, Expression<Func<TSource, bool>> predicate) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);
            return source.Where(userPredicate).LongCount(predicate);
        }

        public static IQueryable<TResult> SelectInUserContext<TSource, TResult>(this IQueryable<TSource> source, HttpContext context, Expression<Func<TSource, TResult>> selector) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);
            return source.Where(userPredicate).Select(selector);
        }

        public static IQueryable<TResult> SelectManyInUserContext<TSource, TResult>(this IQueryable<TSource> source, HttpContext context, Expression<Func<TSource, IEnumerable<TResult>>> selector) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);
            return source.Where(userPredicate).SelectMany(selector);
        }

        public static TSource SingleInUserContext<TSource>(this IQueryable<TSource> source, HttpContext context) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);

            try
            {
                return source.Single(userPredicate);
            }
            catch
            {
                var preUserCount = source.Count();
                var postUserCount = source.Count(userPredicate);

                if (preUserCount == 1 && postUserCount == 0)
                    throw new ItemNotInUserContextException();
                else
                    throw;
            }
        }

        public static TSource SingleInUserContext<TSource>(this IQueryable<TSource> source, HttpContext context, Expression<Func<TSource, bool>> predicate) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);

            try
            {
                return source.Where(userPredicate).Single(predicate);
            }
            catch
            {
                var preUserCount = source.Count(predicate);
                var postUserCount = source.Where(userPredicate).Count(predicate);

                if (preUserCount == 1 && postUserCount == 0)
                    throw new ItemNotInUserContextException();
                else
                    throw;
            }
        }

        public static TSource SingleOrDefaultInUserContext<TSource>(this IQueryable<TSource> source, HttpContext context) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);
            return source.SingleOrDefault(userPredicate);
        }

        public static TSource SingleOrDefaultInUserContext<TSource>(this IQueryable<TSource> source, HttpContext context, Expression<Func<TSource, bool>> predicate) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);
            return source.Where(userPredicate).SingleOrDefault(predicate);
        }

        public static IQueryable<TSource> WhereInUserContext<TSource>(this IQueryable<TSource> source, HttpContext context) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);
            return source.Where(userPredicate);
        }

        public static IQueryable<TSource> WhereInUserContext<TSource>(this IQueryable<TSource> source, HttpContext context, Expression<Func<TSource, bool>> predicate) where TSource : class
        {
            Expression<Func<TSource, bool>> userPredicate = GetUserFilterExpression<TSource>(context);
            return source.Where(predicate).Where(userPredicate);
        }

        private static Expression<Func<TSource, bool>> GetUserFilterExpression<TSource>(HttpContext context) where TSource : class
        {
            Expression<Func<TSource, bool>> finalExpression = null;

            var attrs = typeof(TSource).GetCustomAttributes(true).Where(a => a.GetType() == typeof(UserFilterableAttribute));

            if (attrs.Count() == 0)
            {
                throw new MissingMemberException($"{typeof(TSource).Name} must have a UserFilterableAttribute in order to use one of the UserContext search methods");
            }

            var userClaim = context.User.Claims.SingleOrDefault(c => c.Type == ClaimTypes.NameIdentifier);
            if (userClaim == null) 
                throw new NullReferenceException("There is no user logged in to provide context");
            
            var attrInfo = (UserFilterableAttribute)attrs.Single();
            var parameter = Expression.Parameter(typeof(TSource));

            Expression property = Expression.Property(parameter, attrInfo.PropertyName);

            var userProperty = typeof(TSource).GetProperty(attrInfo.PropertyName);

            object castUserID = GetCastUserID(userClaim, userProperty);

            var constant = Expression.Constant(castUserID);
            var equalClause = Expression.Equal(property, constant);
            finalExpression = Expression.Lambda<Func<TSource, bool>>(equalClause, parameter);

            return finalExpression;
        }


        private static object GetCastUserID(Claim userClaim, PropertyInfo userProperty)
        {
            object castedUserID;
            if (userProperty.PropertyType == typeof(Guid))
                castedUserID = Guid.Parse(userClaim.Value);
            else
                castedUserID = userClaim.Value;

            return castedUserID;
        }
    }
}
