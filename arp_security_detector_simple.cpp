/**
 * @file arp_security_detector.cpp
 * @brief ROS2 Liveliness QoS-based ARP Spoofing Detection System
 * 
 * This tool utilizes ROS2's Liveliness QoS mechanism to detect
 * ARP Spoofing attacks in real-time by monitoring publisher
 * liveliness events and validating ARP cache changes.
 * 
 * Key Features:
 * - Publisher liveliness monitoring via QoS events
 * - Real-time ARP cache validation
 * - MAC address duplication detection (ARP Spoofing)
 * - Simple console-based output
 */

#include <functional>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <sstream>
#include <string>
#include <cstdio>

#include "rclcpp/rclcpp.hpp"
#include "std_msgs/msg/string.hpp"

using std::placeholders::_1;

/**
 * @class ARPSecurityDetector
 * @brief ROS2 node for ARP Spoofing detection using Liveliness QoS
 * 
 * This class monitors publisher liveliness events and uses them as triggers
 * to validate ARP cache changes, detecting potential network attacks.
 */
class ARPSecurityDetector : public rclcpp::Node
{
public:
  /**
   * @brief Constructor - Initialize QoS settings and callbacks
   */
  ARPSecurityDetector()
  : Node("arp_security_detector")
  {
    // Configure Liveliness QoS
    auto qos = rclcpp::QoS(rclcpp::KeepAll()).reliable();
    qos.liveliness(RMW_QOS_POLICY_LIVELINESS_AUTOMATIC);
    qos.liveliness_lease_duration(std::chrono::seconds(1));

    // Set up event callbacks
    rclcpp::SubscriptionOptions options;
    options.event_callbacks.liveliness_callback =
      std::bind(&ARPSecurityDetector::liveliness_callback, this, _1);
    
    // Create subscription
    subscription_ = this->create_subscription<std_msgs::msg::String>(
      "topic", qos, std::bind(&ARPSecurityDetector::topic_callback, this, _1), options);
      
    RCLCPP_INFO(this->get_logger(), "ARP Security Detector initialized");
  }

private:
  /**
   * @brief Update ARP cache by executing 'arp -n' command
   * 
   * This function reads the current ARP cache from the system and
   * stores it for comparison with previous state to detect changes.
   */
  void update_arp_cache()
  {
      RCLCPP_INFO(this->get_logger(), "[ARPC] Executing ARP cache update...");

      std::string command = "arp -n";
      FILE* pipe = popen(command.c_str(), "r");
      if (!pipe) {
        RCLCPP_ERROR(this->get_logger(), "[ARPC] Failed to execute arp command!");
        return;
      }

      char buffer[128];
      std::stringstream result_ss;
      std::lock_guard<std::mutex> lock(arp_cache_mutex_);
      
      // Backup previous cache before clearing
      previous_arp_cache_ = arp_cache_;
      arp_cache_.clear();

      bool is_header = true;
      while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result_ss << buffer;
        if (is_header) {
          is_header = false;
          continue;
        }
        
        // Parse ARP table entries
        std::string line(buffer);
        std::stringstream ss(line);
        std::string ip, hwtype, mac;
        ss >> ip >> hwtype >> mac;
        
        // Store valid entries (skip incomplete ones)
        if (!ip.empty() && !mac.empty() && mac != "(incomplete)") {
          arp_cache_[ip] = mac;
        }
      }
      pclose(pipe);
      
      RCLCPP_INFO(this->get_logger(), "[ARPC] --- ARP Cache Contents ---\n%s--------------------------", result_ss.str().c_str());
      RCLCPP_INFO(this->get_logger(), "[ARPC] ARP Cache update complete. Total %zu entries.", arp_cache_.size());
  }

  /**
   * @brief Verify ARP cache changes and detect security threats
   * 
   * This function compares the current ARP cache with the previous state
   * to detect potential ARP spoofing attacks, including:
   * - New ARP entries
   * - Modified IP-MAC mappings
   * - Removed entries
   * - Duplicate MAC addresses (ARP Spoofing indicator)
   */
  void verify_arp_changes()
  {
    RCLCPP_INFO(this->get_logger(), "[VERIFY] Verifying ARP cache changes...");
    std::lock_guard<std::mutex> lock(arp_cache_mutex_);
    bool has_changes = false;

    // Check for new or modified entries
    for (const auto& new_pair : arp_cache_) {
      auto old_it = previous_arp_cache_.find(new_pair.first);
      if (old_it == previous_arp_cache_.end()) {
        RCLCPP_WARN(this->get_logger(), "[VERIFY] New entry added -> IP: %s, MAC: %s",
          new_pair.first.c_str(), new_pair.second.c_str());
        has_changes = true;
      } else if (old_it->second != new_pair.second) {
        RCLCPP_WARN(this->get_logger(), "[VERIFY-WARN] Entry modified -> IP: %s, OLD MAC: %s, NEW MAC: %s",
          new_pair.first.c_str(), old_it->second.c_str(), new_pair.second.c_str());
        has_changes = true;
      }
    }
    
    // Check for removed entries
    for (const auto& old_pair : previous_arp_cache_) {
      if (arp_cache_.find(old_pair.first) == arp_cache_.end()) {
        RCLCPP_WARN(this->get_logger(), "[VERIFY] Entry removed -> IP: %s, MAC: %s",
          old_pair.first.c_str(), old_pair.second.c_str());
        has_changes = true;
      }
    }

    // Build MAC to IPs mapping for duplicate detection
    std::unordered_map<std::string, std::vector<std::string>> mac_to_ips;
    for (const auto& pair : arp_cache_) {
      mac_to_ips[pair.second].push_back(pair.first);
    }

    // Detect MAC address duplication (ARP Spoofing indicator)
    for (const auto& mac_pair : mac_to_ips) {
      if (mac_pair.second.size() > 1) {
        // Create conflict list string
        std::stringstream conflicting_ips_ss;
        for (size_t i = 0; i < mac_pair.second.size(); ++i) {
          conflicting_ips_ss << mac_pair.second[i] << (i == mac_pair.second.size() - 1 ? "" : ", ");
        }
        
        // Critical security alert
        RCLCPP_ERROR(this->get_logger(),
          "[VERIFY-FATAL] Duplicate MAC detected! MAC: [%s] is used by IPs: [%s]",
          mac_pair.first.c_str(), conflicting_ips_ss.str().c_str());
        has_changes = true;
      }
    }

    if (!has_changes) {
      RCLCPP_INFO(this->get_logger(), "[VERIFY] No changes detected in ARP cache.");
    }
  }

  /**
   * @brief Liveliness QoS event callback
   * @param event Liveliness change information
   * 
   * This callback is triggered when publisher liveliness status changes.
   * When a publisher becomes inactive, it triggers ARP cache validation
   * to detect potential network attacks.
   */
  void liveliness_callback(rclcpp::QOSLivelinessChangedInfo &event)
  {
    RCLCPP_INFO(this->get_logger(),
      "[ARPC] Liveliness changed event: alive_count=%d, not_alive_count=%d",
      event.alive_count, event.not_alive_count);

    if (event.not_alive_count > 0) {
      RCLCPP_WARN(this->get_logger(), "[ARPC] A publisher is no longer alive...");
      update_arp_cache();
      verify_arp_changes();
    }
  }
  
  /**
   * @brief Topic message callback
   * @param msg Received message
   * 
   * This callback processes incoming messages and initializes
   * the ARP cache baseline on first message reception.
   */
  void topic_callback(const std_msgs::msg::String & msg) 
  {
    // Initialize ARP cache baseline on first message
    if (!is_first_message_received_) {
      RCLCPP_INFO(this->get_logger(), "First message received. Initializing ARP cache baseline.");
      update_arp_cache();
      is_first_message_received_ = true;
    }
    
    // Increment message counter
    messages_received_++;
    
    RCLCPP_INFO(this->get_logger(), 
    "[RECV]: '%s' | Total messages: %zu",  
    msg.data.c_str(), messages_received_);
  }
  
  // Member variables
  rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscription_;

  std::unordered_map<std::string, std::string> arp_cache_;           ///< Current ARP cache
  std::mutex arp_cache_mutex_;                                       ///< Mutex for thread safety
  
  bool is_first_message_received_ = false;                          ///< First message flag
  std::unordered_map<std::string, std::string> previous_arp_cache_; ///< Previous ARP cache state
  size_t messages_received_ = 0;                                     ///< Message counter
};

/**
 * @brief Main function
 * @param argc Argument count
 * @param argv Argument vector
 * @return Exit code
 */
int main(int argc, char * argv[])
{
  rclcpp::init(argc, argv);
  rclcpp::spin(std::make_shared<ARPSecurityDetector>());
  rclcpp::shutdown();
  return 0;
}
