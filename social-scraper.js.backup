#!/usr/bin/env node

const axios = require('axios');
const fs = require('fs');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

// ============================================
// SOCIAL MEDIA SCRAPER
// ============================================

const PLATFORMS = {
  instagram: {
    name: 'Instagram',
    profileUrl: 'https://www.instagram.com/',
    apiUrl: 'https://www.instagram.com/api/v1/users/web_profile_info/?username=',
    features: ['posts', 'followers', 'following', 'bio', 'profile_pic']
  },
  twitter: {
    name: 'Twitter/X',
    profileUrl: 'https://twitter.com/',
    features: ['tweets', 'followers', 'following', 'bio', 'verified']
  },
  tiktok: {
    name: 'TikTok',
    profileUrl: 'https://www.tiktok.com/@',
    features: ['videos', 'followers', 'following', 'likes']
  },
  facebook: {
    name: 'Facebook',
    profileUrl: 'https://www.facebook.com/',
    features: ['posts', 'friends', 'photos', 'about']
  },
  linkedin: {
    name: 'LinkedIn',
    profileUrl: 'https://www.linkedin.com/in/',
    features: ['connections', 'experience', 'education', 'skills']
  },
  github: {
    name: 'GitHub',
    profileUrl: 'https://github.com/',
    apiUrl: 'https://api.github.com/users/',
    features: ['repos', 'followers', 'following', 'contributions']
  },
  reddit: {
    name: 'Reddit',
    profileUrl: 'https://www.reddit.com/user/',
    apiUrl: 'https://www.reddit.com/user/{}/about.json',
    features: ['posts', 'comments', 'karma', 'awards']
  }
};

async function scrapeGitHub(username) {
  try {
    console.log(`   Scraping GitHub profile...`);
    
    const response = await axios.get(`https://api.github.com/users/${username}`, {
      headers: {
        'User-Agent': 'NIKA-OSINT/4.0',
        'Accept': 'application/vnd.github.v3+json'
      }
    });
    
    const user = response.data;
    
    // Get repos
    const reposResponse = await axios.get(user.repos_url, {
      headers: {
        'User-Agent': 'NIKA-OSINT/4.0'
      }
    });
    
    const repos = reposResponse.data.slice(0, 10).map(repo => ({
      name: repo.name,
      description: repo.description,
      stars: repo.stargazers_count,
      forks: repo.forks_count,
      language: repo.language,
      url: repo.html_url,
      created: repo.created_at,
      updated: repo.updated_at
    }));
    
    return {
      platform: 'GitHub',
      username: username,
      available: true,
      profile: {
        name: user.name,
        bio: user.bio,
        company: user.company,
        location: user.location,
        email: user.email,
        blog: user.blog,
        twitter: user.twitter_username,
        followers: user.followers,
        following: user.following,
        publicRepos: user.public_repos,
        publicGists: user.public_gists,
        created: user.created_at,
        updated: user.updated_at,
        profileUrl: user.html_url,
        avatarUrl: user.avatar_url
      },
      repos: repos,
      stats: {
        totalStars: repos.reduce((sum, r) => sum + r.stars, 0),
        totalForks: repos.reduce((sum, r) => sum + r.forks, 0),
        languages: [...new Set(repos.map(r => r.language).filter(Boolean))]
      }
    };
  } catch (error) {
    return {
      platform: 'GitHub',
      username: username,
      available: false,
      error: error.response?.status === 404 ? 'User not found' : error.message
    };
  }
}

async function scrapeReddit(username) {
  try {
    console.log(`   Scraping Reddit profile...`);
    
    const response = await axios.get(`https://www.reddit.com/user/${username}/about.json`, {
      headers: {
        'User-Agent': 'NIKA-OSINT/4.0'
      }
    });
    
    const user = response.data.data;
    
    // Get recent posts
    const postsResponse = await axios.get(`https://www.reddit.com/user/${username}.json?limit=10`, {
      headers: {
        'User-Agent': 'NIKA-OSINT/4.0'
      }
    });
    
    const posts = postsResponse.data.data.children.map(post => ({
      title: post.data.title,
      subreddit: post.data.subreddit,
      score: post.data.score,
      comments: post.data.num_comments,
      created: new Date(post.data.created_utc * 1000).toISOString(),
      url: `https://reddit.com${post.data.permalink}`
    }));
    
    return {
      platform: 'Reddit',
      username: username,
      available: true,
      profile: {
        name: user.name,
        created: new Date(user.created_utc * 1000).toISOString(),
        karma: {
          post: user.link_karma,
          comment: user.comment_karma,
          total: user.total_karma
        },
        isPremium: user.is_gold,
        isMod: user.is_mod,
        hasVerifiedEmail: user.has_verified_email,
        profileUrl: `https://reddit.com/user/${username}`,
        iconUrl: user.icon_img
      },
      recentPosts: posts,
      stats: {
        totalPosts: posts.length,
        avgScore: posts.reduce((sum, p) => sum + p.score, 0) / posts.length || 0,
        subreddits: [...new Set(posts.map(p => p.subreddit))]
      }
    };
  } catch (error) {
    return {
      platform: 'Reddit',
      username: username,
      available: false,
      error: error.response?.status === 404 ? 'User not found' : error.message
    };
  }
}

async function scrapeInstagram(username) {
  // Instagram requires auth now, so we'll provide manual instructions
  return {
    platform: 'Instagram',
    username: username,
    available: false,
    note: 'Instagram scraping requires authentication',
    manualUrl: `https://www.instagram.com/${username}/`,
    alternatives: [
      `Use Osintgram: https://github.com/Datalux/Osintgram`,
      `Use Instaloader: pkg install python && pip install instaloader`,
      `Manual inspection via browser`
    ],
    tools: {
      osintgram: 'python3 osintgram.py {username}',
      instaloader: `instaloader profile ${username}`
    }
  };
}

async function scrapeTwitter(username) {
  return {
    platform: 'Twitter/X',
    username: username,
    available: false,
    note: 'Twitter API requires authentication',
    manualUrl: `https://twitter.com/${username}`,
    alternatives: [
      `Use Twint: pip install twint`,
      `Use Nitter: https://nitter.net/${username}`,
      `Manual inspection via browser`
    ],
    tools: {
      twint: `twint -u ${username}`,
      nitter: `https://nitter.net/${username}`
    }
  };
}

async function scrapeTikTok(username) {
  return {
    platform: 'TikTok',
    username: username,
    available: false,
    note: 'TikTok scraping requires API/tools',
    manualUrl: `https://www.tiktok.com/@${username}`,
    alternatives: [
      `Use TikTok-Api: pip install TikTokApi`,
      `Manual inspection via browser`
    ]
  };
}

async function scrapeAllPlatforms(username) {
  console.log(`\n⏳ Scraping all platforms for: ${username}...\n`);
  
  const results = {
    username: username,
    timestamp: new Date().toISOString(),
    platforms: []
  };
  
  // GitHub (works without auth)
  results.platforms.push(await scrapeGitHub(username));
  
  // Reddit (works without auth)
  results.platforms.push(await scrapeReddit(username));
  
  // Instagram (requires tools)
  results.platforms.push(await scrapeInstagram(username));
  
  // Twitter (requires tools)
  results.platforms.push(await scrapeTwitter(username));
  
  // TikTok (requires tools)
  results.platforms.push(await scrapeTikTok(username));
  
  return results;
}

function showBanner() {
  console.log("\x1b[31m");
  console.log("███████╗ ██████╗  ██████╗██╗ █████╗ ██╗         ███████╗ ██████╗██████╗  █████╗ ██████╗ ███████╗██████╗ ");
  console.log("██╔════╝██╔═══██╗██╔════╝██║██╔══██╗██║         ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗");
  console.log("███████╗██║   ██║██║     ██║███████║██║         ███████╗██║     ██████╔╝███████║██████╔╝█████╗  ██████╔╝");
  console.log("╚════██║██║   ██║██║     ██║██╔══██║██║         ╚════██║██║     ██╔══██╗██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗");
  console.log("███████║╚██████╔╝╚██████╗██║██║  ██║███████╗    ███████║╚██████╗██║  ██║██║  ██║██║     ███████╗██║  ██║");
  console.log("╚══════╝ ╚═════╝  ╚═════╝╚═╝╚═╝  ╚═╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝");
  console.log("\x1b[0m");
  console.log("\x1b[35m🥝 NIKA Social Media Scraper - Extract public data from social platforms\x1b[0m");
  console.log("\x1b[33m⚠️  For authorized investigation only - Respect privacy and ToS\x1b[0m\n");
}

function displayResults(data) {
  console.log("\n╔════════════════════════════════════════════════════════╗");
  console.log("║       📱 SOCIAL MEDIA SCRAPER RESULTS 📱               ║");
  console.log("╚════════════════════════════════════════════════════════╝\n");
  
  console.log(`👤 Username: \x1b[36m${data.username}\x1b[0m`);
  console.log(`⏰ Scanned: ${new Date(data.timestamp).toLocaleString()}\n`);
  
  data.platforms.forEach(platform => {
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    console.log(`\x1b[36m${platform.platform}\x1b[0m`);
    console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    
    if (!platform.available) {
      console.log(`   \x1b[33m⚠️  ${platform.error || platform.note}\x1b[0m`);
      
      if (platform.manualUrl) {
        console.log(`   Manual URL: ${platform.manualUrl}`);
      }
      
      if (platform.alternatives) {
        console.log(`\n   Alternatives:`);
        platform.alternatives.forEach(alt => {
          console.log(`   • ${alt}`);
        });
      }
      
      if (platform.tools) {
        console.log(`\n   Tools:`);
        Object.entries(platform.tools).forEach(([name, cmd]) => {
          console.log(`   ${name}: ${cmd}`);
        });
      }
      
      console.log('');
      return;
    }
    
    // GitHub results
    if (platform.platform === 'GitHub' && platform.profile) {
      console.log(`   \x1b[32m✓ Profile Found\x1b[0m`);
      console.log(`   Name: ${platform.profile.name || 'N/A'}`);
      console.log(`   Bio: ${platform.profile.bio || 'N/A'}`);
      console.log(`   Location: ${platform.profile.location || 'N/A'}`);
      console.log(`   Company: ${platform.profile.company || 'N/A'}`);
      console.log(`   Email: ${platform.profile.email || 'N/A'}`);
      console.log(`   Blog: ${platform.profile.blog || 'N/A'}`);
      console.log(`   Followers: ${platform.profile.followers}`);
      console.log(`   Following: ${platform.profile.following}`);
      console.log(`   Public Repos: ${platform.profile.publicRepos}`);
      console.log(`   Created: ${new Date(platform.profile.created).toLocaleDateString()}`);
      console.log(`   Profile: ${platform.profile.profileUrl}`);
      
      if (platform.repos.length > 0) {
        console.log(`\n   Recent Repositories:`);
        platform.repos.slice(0, 5).forEach((repo, i) => {
          console.log(`   ${i + 1}. ${repo.name} (⭐ ${repo.stars})`);
          console.log(`      ${repo.description || 'No description'}`);
          console.log(`      Language: ${repo.language || 'N/A'}`);
          console.log(`      ${repo.url}`);
        });
      }
      
      if (platform.stats) {
        console.log(`\n   Stats:`);
        console.log(`   Total Stars: ${platform.stats.totalStars}`);
        console.log(`   Total Forks: ${platform.stats.totalForks}`);
        console.log(`   Languages: ${platform.stats.languages.join(', ')}`);
      }
    }
    
    // Reddit results
    if (platform.platform === 'Reddit' && platform.profile) {
      console.log(`   \x1b[32m✓ Profile Found\x1b[0m`);
      console.log(`   Username: ${platform.profile.name}`);
      console.log(`   Post Karma: ${platform.profile.karma.post.toLocaleString()}`);
      console.log(`   Comment Karma: ${platform.profile.karma.comment.toLocaleString()}`);
      console.log(`   Total Karma: ${platform.profile.karma.total.toLocaleString()}`);
      console.log(`   Premium: ${platform.profile.isPremium ? 'Yes' : 'No'}`);
      console.log(`   Moderator: ${platform.profile.isMod ? 'Yes' : 'No'}`);
      console.log(`   Created: ${new Date(platform.profile.created).toLocaleDateString()}`);
      console.log(`   Profile: ${platform.profile.profileUrl}`);
      
      if (platform.recentPosts.length > 0) {
        console.log(`\n   Recent Posts:`);
        platform.recentPosts.slice(0, 5).forEach((post, i) => {
          console.log(`   ${i + 1}. ${post.title}`);
          console.log(`      r/${post.subreddit} | ⬆️ ${post.score} | 💬 ${post.comments}`);
          console.log(`      ${post.url}`);
        });
      }
      
      if (platform.stats) {
        console.log(`\n   Stats:`);
        console.log(`   Avg Score: ${platform.stats.avgScore.toFixed(1)}`);
        console.log(`   Active Subreddits: ${platform.stats.subreddits.join(', ')}`);
      }
    }
    
    console.log('');
  });
  
  // Summary
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
  console.log("\x1b[36m📊 SUMMARY\x1b[0m");
  console.log("\x1b[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
  
  const found = data.platforms.filter(p => p.available).length;
  const notFound = data.platforms.filter(p => !p.available).length;
  
  console.log(`   Profiles Found: \x1b[32m${found}\x1b[0m`);
  console.log(`   Profiles Not Found: \x1b[33m${notFound}\x1b[0m`);
  console.log('');
}

function saveResults(data) {
  const dir = './social-scraper-reports';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const jsonFile = `${dir}/${data.username}-${timestamp}.json`;
  const txtFile = jsonFile.replace('.json', '.txt');
  
  fs.writeFileSync(jsonFile, JSON.stringify(data, null, 2));
  
  let txtContent = `═══════════════════════════════════════════════════════════
SOCIAL MEDIA SCRAPER REPORT
═══════════════════════════════════════════════════════════

Username: ${data.username}
Date: ${new Date(data.timestamp).toLocaleString()}

═══════════════════════════════════════════════════════════
PLATFORMS SCANNED
═══════════════════════════════════════════════════════════

`;

  data.platforms.forEach(platform => {
    txtContent += `${platform.platform}\n`;
    txtContent += `${'─'.repeat(50)}\n`;
    
    if (!platform.available) {
      txtContent += `Status: Not Found\n`;
      txtContent += `Note: ${platform.error || platform.note}\n\n`;
      return;
    }
    
    txtContent += `Status: Found\n\n`;
    
    if (platform.profile) {
      txtContent += `Profile:\n`;
      Object.entries(platform.profile).forEach(([key, value]) => {
        if (typeof value === 'object') {
          txtContent += `${key}:\n`;
          Object.entries(value).forEach(([k, v]) => {
            txtContent += `  ${k}: ${v}\n`;
          });
        } else {
          txtContent += `${key}: ${value}\n`;
        }
      });
    }
    
    txtContent += '\n';
  });
  
  fs.writeFileSync(txtFile, txtContent);
  
  console.log(`\x1b[32m✅ Results saved:\x1b[0m`);
  console.log(`   JSON: ${jsonFile}`);
  console.log(`   TXT: ${txtFile}\n`);
}

function showHelp() {
  showBanner();
  
  console.log("Usage: node social-scraper.js [OPTIONS] <username>\n");
  console.log("Options:");
  console.log("  --platform <name>  Scrape specific platform (github, reddit, instagram, twitter, tiktok)");
  console.log("  --save             Save results to file");
  console.log("  --help             Show this help\n");
  
  console.log("Examples:");
  console.log("  node social-scraper.js kiwi");
  console.log("  node social-scraper.js --platform github kiwi");
  console.log("  node social-scraper.js kiwi --save\n");
  
  console.log("\x1b[33mSupported Platforms:\x1b[0m");
  console.log("  • GitHub (full scraping)");
  console.log("  • Reddit (full scraping)");
  console.log("  • Instagram (manual/tools required)");
  console.log("  • Twitter/X (manual/tools required)");
  console.log("  • TikTok (manual/tools required)\n");
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.length === 0) {
    showHelp();
    process.exit(0);
  }
  
  let username = null;
  let platform = null;
  let saveResults_flag = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--platform' && args[i + 1]) {
      platform = args[i + 1];
      i++;
    } else if (args[i] === '--save') {
      saveResults_flag = true;
    } else if (!args[i].startsWith('--')) {
      username = args[i];
    }
  }
  
  if (!username) {
    console.log("\x1b[31m❌ No username specified!\x1b[0m\n");
    showHelp();
    process.exit(1);
  }
  
  showBanner();
  
  let results;
  
  if (platform) {
    console.log(`⏳ Scraping ${platform} for: ${username}...\n`);
    
    switch(platform.toLowerCase()) {
      case 'github':
        results = {
          username,
          timestamp: new Date().toISOString(),
          platforms: [await scrapeGitHub(username)]
        };
        break;
      case 'reddit':
        results = {
          username,
          timestamp: new Date().toISOString(),
          platforms: [await scrapeReddit(username)]
        };
        break;
      case 'instagram':
        results = {
          username,
          timestamp: new Date().toISOString(),
          platforms: [await scrapeInstagram(username)]
        };
        break;
      case 'twitter':
        results = {
          username,
          timestamp: new Date().toISOString(),
          platforms: [await scrapeTwitter(username)]
        };
        break;
      case 'tiktok':
        results = {
          username,
          timestamp: new Date().toISOString(),
          platforms: [await scrapeTikTok(username)]
        };
        break;
      default:
        console.log(`\x1b[31m❌ Invalid platform: ${platform}\x1b[0m\n`);
        process.exit(1);
    }
  } else {
    results = await scrapeAllPlatforms(username);
  }
  
  displayResults(results);
  
  if (saveResults_flag) {
    saveResults(results);
  }
  
  console.log("\x1b[31m███████╗ ██████╗  ██████╗██╗ █████╗ ██╗\x1b[0m");
  console.log("\x1b[35m🥝 Scraping complete - by kiwi & 777\x1b[0m\n");
}

main().catch(console.error);
